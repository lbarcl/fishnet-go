package repo

type FrameFlags uint8

const (
	FlagNone       FrameFlags = 0
	FlagGzip       FrameFlags = 1 << 0
	FlagRequestTLS FrameFlags = 1 << 1
	FlagStartTLS   FrameFlags = 1 << 2
)
