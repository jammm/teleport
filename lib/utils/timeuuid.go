package utils

import (
	"time"

	"encoding/binary"
)

func MaxTimeUUID(tm time.Time) []byte {
	return fromTimeAndBits(tm, maxClockSeqAndNode)
}

func MinTimeUUID(tm time.Time) []byte {
	return fromTimeAndBits(tm, minClockSeqAndNode)
}

// fromTimeAndBits composes fake UUID based on given time
// and most significant bits
func fromTimeAndBits(tm time.Time, highBits uint64) []byte {
	bytes := make([]byte, 16)

	utcTime := tm.In(time.UTC)

	// according to https://tools.ietf.org/html/rfc4122#page-8 time portion is
	// count of 100 nanosecond intervals since 00:00:00.00, 15 October 1582 (the date of
	// Gregorian reform to the Christian calendar).
	count := uint64(utcTime.Unix()-timeBase)*10000000 + uint64(utcTime.Nanosecond()/100)

	low := uint32(count & 0xffffffff)
	mid := uint16((count >> 32) & 0xffff)
	hi := uint16((count >> 48) & 0x0fff)
	hi |= 0x1000 // Version 1

	binary.BigEndian.PutUint32(bytes[0:], low)
	binary.BigEndian.PutUint16(bytes[4:], mid)
	binary.BigEndian.PutUint16(bytes[6:], hi)
	binary.BigEndian.PutUint64(bytes[8:], highBits)

	return bytes
}

// the date of Gregorian reform to the Christian calendar
var timeBase = time.Date(1582, time.October, 15, 0, 0, 0, 0, time.UTC).Unix()

const (
	minClockSeqAndNode uint64 = 0x8080808080808080
	maxClockSeqAndNode uint64 = 0x7f7f7f7f7f7f7f7f
)
