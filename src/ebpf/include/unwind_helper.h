/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once
#include <functional>
class _unwind_helper {
public:
  _unwind_helper(std::function<void()> unwind) : _unwind(unwind) {}

  ~_unwind_helper() { _unwind(); }

private:
  std::function<void()> _unwind;
};
