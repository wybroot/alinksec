package virusscan

// A bounded pool avoids allocation churn during large scans. Reclamation never
// drops signatures, trusted policy, reports or detection metadata baselines.
var readBuffers = make(chan []byte, 2)

func acquireReadBuffer() []byte {
	select {
	case b := <-readBuffers:
		return b
	default:
		return make([]byte, 64<<10)
	}
}
func releaseReadBuffer(b []byte) {
	select {
	case readBuffers <- b:
	default:
	}
}
func TrimReadBuffers() {
	for {
		select {
		case <-readBuffers:
		default:
			return
		}
	}
}
