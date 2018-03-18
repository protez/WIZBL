// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Wizbl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WIZBL_UTILTIME_H
#define WIZBL_UTILTIME_H

#include <stdint.h>
#include <string>

/**
 * getTimeMicros() and getTimeMillis() both return the system time, but in
 * different units. getTime() returns the system time in seconds, but also
 * supports mocktime, where the time can be specified by the user, eg for
 * testing (eg with the setmocktime rpc, or -mocktime argument).
 *
 * TODO: Rework these functions to be type-safe (so that we don't inadvertently
 * compare numbers with different units, or compare a mocktime to system time).
 */

int64_t getTime();
int64_t getTimeMillis();
int64_t getTimeMicros();
int64_t getSystemTimeInSeconds(); // Like getTime(), but not mockable
void setMockTime(int64_t nMockTimeIn);
int64_t getMockTime();
void MilliSleep(int64_t n);

std::string DateTimeStrFormat(const char* pszFormat, int64_t nTime);

#endif // WIZBL_UTILTIME_H
