package agent

import (
	"context"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// PodEvent represents a pod add/update/delete from the cluster
type PodEvent struct {
	Type string // "ADD", "UPDATE", "DELETE"
	Pod  *corev1.Pod
}

// Watcher watches for pod changes in the cluster using informers.
// New or changed pods trigger vulnerability scans.
type Watcher struct {
	client kubernetes.Interface
	events chan PodEvent
	store  cache.Store // set once Run() syncs the cache
	log    *zap.Logger
}

func NewWatcher(client kubernetes.Interface, log *zap.Logger) *Watcher {
	return &Watcher{
		client: client,
		events: make(chan PodEvent, 256),
		log:    log,
	}
}

func (w *Watcher) Events() <-chan PodEvent {
	return w.events
}

// Pods returns all pods currently known to the informer cache.
// Used for periodic re-scans.
func (w *Watcher) Pods() []*corev1.Pod {
	if w.store == nil {
		return nil
	}
	objs := w.store.List()
	pods := make([]*corev1.Pod, 0, len(objs))
	for _, obj := range objs {
		if pod, ok := obj.(*corev1.Pod); ok {
			pods = append(pods, pod)
		}
	}
	return pods
}

func (w *Watcher) Run(ctx context.Context) error {
	factory := informers.NewSharedInformerFactory(w.client, 0)
	podInformer := factory.Core().V1().Pods().Informer()

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			w.log.Debug("pod added", zap.String("pod", pod.Name), zap.String("namespace", pod.Namespace))
			w.send(PodEvent{Type: "ADD", Pod: pod})
		},
		UpdateFunc: func(_, newObj interface{}) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				return
			}
			w.send(PodEvent{Type: "UPDATE", Pod: pod})
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			w.send(PodEvent{Type: "DELETE", Pod: pod})
		},
	})

	w.store = podInformer.GetStore()

	factory.Start(ctx.Done())
	factory.WaitForCacheSync(ctx.Done())

	<-ctx.Done()
	return ctx.Err()
}

func (w *Watcher) send(e PodEvent) {
	select {
	case w.events <- e:
	default:
		w.log.Warn("pod event channel full, dropping event",
			zap.String("pod", e.Pod.Name))
	}
}
