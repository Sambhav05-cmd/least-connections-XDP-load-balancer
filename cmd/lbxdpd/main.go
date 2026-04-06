package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf lb  ../../bpf/lb_lc_est.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf lb2 ../../bpf/lb_lc_syn.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf lb3 ../../bpf/lb_wlc_est.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf lb4 ../../bpf/lb_wlc_syn.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf lb5 ../../bpf/lb_rr_est.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf lb6 ../../bpf/lb_rr_syn.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf lb7 ../../bpf/lb_wrr_est.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf lb8 ../../bpf/lb_wrr_syn.c

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	pb "lb/proto"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"google.golang.org/grpc"
)

// variant is the unified interface implemented by all combinations of
// (algo=lc|wlc|rr|wrr) × (mode=est|syn).
type variant interface {
	Program() *ebpf.Program
	Init(cfgPath string) error
	Close()

	// Weight update is a no-op for lc and rr variants.
	UpdateWeight(ip string, port uint16, weight uint16) error

	AddBackend(ip string, port uint16, weight uint16) error
	DeleteBackend(ip string, port uint16) error
	AddService(ip string, port uint16) error
	DeleteService(ip string, port uint16) error
}

func main() {
	iface   := flag.String("i", "lo", "network interface to attach XDP program to")
	algo    := flag.String("algo", "lc", "load-balancing algorithm: lc, wlc, rr, or wrr")
	mode    := flag.String("mode", "est", "connection-tracking mode: est or syn")
	cfgPath := flag.String("config", "", "path to backends config JSON (default: configs/backends_<algo>.json)")
	sock    := flag.String("sock", "/var/run/lbxdpd.sock", "gRPC unix socket path")
	flag.Parse()

	// Default config path based on algo when not explicitly set.
	// rr reuses lc config; wrr reuses wlc config.
	if *cfgPath == "" {
		switch *algo {
		case "rr":
			*cfgPath = "configs/backends_lc.json"
		case "wrr":
			*cfgPath = "configs/backends_wlc.json"
		default:
			*cfgPath = "configs/backends_" + *algo + ".json"
		}
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	cleanPins()

	var (
		v   variant
		err error
	)
	switch *algo {
	case "lc":
		switch *mode {
		case "est":
			v, err = newLcEstVariant()
		case "syn":
			v, err = newLcSynVariant()
		default:
			log.Fatalf("unknown mode %q — want est or syn", *mode)
		}
	case "wlc":
		switch *mode {
		case "est":
			v, err = newWlcEstVariant()
		case "syn":
			v, err = newWlcSynVariant()
		default:
			log.Fatalf("unknown mode %q — want est or syn", *mode)
		}
	case "rr":
		switch *mode {
		case "est":
			v, err = newRrEstVariant()
		case "syn":
			v, err = newRrSynVariant()
		default:
			log.Fatalf("unknown mode %q — want est or syn", *mode)
		}
	case "wrr":
		switch *mode {
		case "est":
			v, err = newWrrEstVariant()
		case "syn":
			v, err = newWrrSynVariant()
		default:
			log.Fatalf("unknown mode %q — want est or syn", *mode)
		}
	default:
		log.Fatalf("unknown algo %q — want lc, wlc, rr, or wrr", *algo)
	}
	if err != nil {
		log.Fatalf("create variant: %v", err)
	}
	defer v.Close()

	if err := v.Init(*cfgPath); err != nil {
		log.Fatalf("init: %v", err)
	}

	ifc, err := net.InterfaceByName(*iface)
	if err != nil {
		log.Fatalf("interface %q: %v", *iface, err)
	}
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   v.Program(),
		Interface: ifc.Index,
	})
	if err != nil {
		log.Fatalf("attach XDP: %v", err)
	}
	defer xdpLink.Close()

	lis, err := net.Listen("unix", *sock)
	if err != nil {
		log.Fatalf("listen %s: %v", *sock, err)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterWeightControlServer(grpcServer, &controlServer{v: v})

	go func() {
		log.Printf("gRPC control listening on %s", *sock)
		if err := grpcServer.Serve(lis); err != nil {
			log.Printf("gRPC serve: %v", err)
		}
	}()

	// Adaptive weight loop only started in weighted modes.
	if *algo == "wlc" || *algo == "wrr" {
		go adaptiveLoop()
	}

	log.Printf("lbxdpd running  iface=%s algo=%s mode=%s config=%s",
		*iface, *algo, *mode, *cfgPath)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	log.Println("shutting down")
	grpcServer.GracefulStop()
}

func adaptiveLoop() {
	t := time.NewTicker(500 * time.Millisecond)
	for range t.C {
		// Future: auto-adjust weights based on live connection counts.
	}
}

// cleanPins removes any pinned BPF maps from a previous run.
func cleanPins() {
	pins := []string{
		"/sys/fs/bpf/lbxdp/backends",
		"/sys/fs/bpf/lbxdp/backend_count",
		"/sys/fs/bpf/lbxdp/services",
		"/sys/fs/bpf/lbxdp/conntrack",
	}
	for _, p := range pins {
		os.Remove(p)
	}
	os.Remove("/run/lbxdp.mode")
}

// ── gRPC server ───────────────────────────────────────────────────────────────

type controlServer struct {
	pb.UnimplementedWeightControlServer
	v variant
}

func (s *controlServer) UpdateWeight(ctx context.Context, r *pb.WeightRequest) (*pb.Empty, error) {
	if err := s.v.UpdateWeight(r.Ip, uint16(r.Port), uint16(r.Weight)); err != nil {
		return nil, err
	}
	return &pb.Empty{}, nil
}

func (s *controlServer) AddBackend(ctx context.Context, r *pb.AddBackendRequest) (*pb.Empty, error) {
	if err := s.v.AddBackend(r.Ip, uint16(r.Port), uint16(r.Weight)); err != nil {
		return nil, err
	}
	return &pb.Empty{}, nil
}

func (s *controlServer) DeleteBackend(ctx context.Context, r *pb.DeleteBackendRequest) (*pb.Empty, error) {
	if err := s.v.DeleteBackend(r.Ip, uint16(r.Port)); err != nil {
		return nil, err
	}
	return &pb.Empty{}, nil
}

func (s *controlServer) AddService(ctx context.Context, r *pb.ServiceRequest) (*pb.Empty, error) {
	if err := s.v.AddService(r.Ip, uint16(r.Port)); err != nil {
		return nil, err
	}
	return &pb.Empty{}, nil
}

func (s *controlServer) DeleteService(ctx context.Context, r *pb.ServiceRequest) (*pb.Empty, error) {
	if err := s.v.DeleteService(r.Ip, uint16(r.Port)); err != nil {
		return nil, err
	}
	return &pb.Empty{}, nil
}