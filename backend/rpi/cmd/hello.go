package cmd

import "time"

type Hello struct {
	Name    string    `json:"name"`
	Version string    `json:"version"`
	Uptime  int64     `json:"uptime"`
	Boot    time.Time `json:"boot"`
	Remote  string    `json:"remote"`
	DecodedData
}
