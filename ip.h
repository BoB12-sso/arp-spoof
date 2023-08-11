#pragma once

#include <cstdint>
#include <string>

struct Ip final {
	static const int SIZE = 4;

	// constructor
	Ip() {}
	Ip(const uint32_t r) : ip_(r) {}
	Ip(const std::string r);

	// casting operator
	operator uint32_t() const { return ip_; } // default
	explicit operator std::string() const;

	// comparison operator
	bool operator == (const Ip& r) const { return ip_ == r.ip_; }

	bool isLocalHost() const { // 127.*.*.*
		uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return prefix == 0x7F;
	}

	bool isBroadcast() const { // 255.255.255.255
		return ip_ == 0xFFFFFFFF;
	}

	bool isMulticast() const { // 224.0.0.0 ~ 239.255.255.255
		uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return prefix >= 0xE0 && prefix < 0xF0;
	}

	void print() const {
		char buf[32] ={0,}; // enough size
		sprintf(buf, "%u.%u.%u.%u",
			(ip_ & 0xFF000000) >> 24,
			(ip_ & 0x00FF0000) >> 16,
			(ip_ & 0x0000FF00) >> 8,
			(ip_ & 0x000000FF));
		printf("%s\n",buf);
		return ;    
	}

protected:
	uint32_t ip_;
};
