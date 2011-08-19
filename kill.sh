#!/bin/bash
kill -9 `ps -aef | grep 'ofdatapath' | grep -v grep | awk '{print $2}'`
kill -9 `ps -aef | grep 'ofprotocol' | grep -v grep | awk '{print $2}'`
