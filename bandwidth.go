package quicwrapper

import (
	"math"
	"sync"
	"time"

	"github.com/getlantern/ema"
	quic "github.com/getlantern/quic-go"
)

type Bandwidth = quic.Bandwidth

const (
	Mib = 1024 * 1024 // 1 Mebibit Bandwidth
)

type BandwidthEstimator interface {
	BandwidthEstimate() Bandwidth
}

const (
	EMABandwidthSamplerDefaultPeriod = 1 * time.Second
	EMABandwidthSamplerDefaultWindow = 15 * time.Second
)

// Samples and averages bandwidth estimates from another
// BandwidthEstimator
type EMABandwidthSampler struct {
	estimate *ema.EMA
	source   BandwidthEstimator
	period   time.Duration
	window   time.Duration
	done     chan struct{}
	start    sync.Once
	stop     sync.Once
}

func NewEMABandwidthSampler(from BandwidthEstimator) *EMABandwidthSampler {
	return NewEMABandwidthSamplerParams(from, EMABandwidthSamplerDefaultPeriod, EMABandwidthSamplerDefaultWindow)
}

func NewEMABandwidthSamplerParams(from BandwidthEstimator, period time.Duration, window time.Duration) *EMABandwidthSampler {

	alpha := 1.0 - math.Exp(-float64(period)/float64(window))

	return &EMABandwidthSampler{
		estimate: ema.New(0, alpha),
		source:   from,
		period:   period,
		done:     make(chan struct{}),
	}
}

func (bs *EMABandwidthSampler) BandwidthEstimate() Bandwidth {
	return Bandwidth(bs.estimate.Get())
}

func (bs *EMABandwidthSampler) Start() {
	bs.start.Do(func() {
		go func() {
			for {
				select {
				case <-bs.done:
					return
				case <-time.After(bs.period):
					bs.update()
				}
			}
		}()
	})
}

func (bs *EMABandwidthSampler) Stop() {
	bs.stop.Do(func() {
		close(bs.done)
	})
}

func (bs *EMABandwidthSampler) Clear() {
	bs.estimate.Clear()
}

func (bs *EMABandwidthSampler) update() {
	sample := bs.source.BandwidthEstimate()
	bs.estimate.Update(float64(sample))
}
