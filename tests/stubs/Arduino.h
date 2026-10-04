#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string>
#include <stdio.h>
using String = std::string;
inline uint32_t& clockMs() { static uint32_t t = 0; return t; }
inline uint32_t millis() { return clockMs(); }
inline void delay(unsigned ms) { clockMs() += ms; }
