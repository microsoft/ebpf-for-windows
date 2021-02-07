/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/

#pragma once
#include <functional>
class UnwindHelper
{
public:
    UnwindHelper(std::function<void()> unwind) : unwind(unwind)
    {
    }

    ~UnwindHelper()
    {
        unwind();
    }
private:
    std::function<void()> unwind;
};

