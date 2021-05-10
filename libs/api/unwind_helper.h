/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once
#include <functional>
/**
 * @brief A helper object to invoke a function when the object goes out of
 * scope.
 *
 */
class _unwind_helper
{
  public:
    /**
     * @brief Construct a new unwind helper object
     *
     * @param[in] unwind Function to invoke when the unwind object is destroyed.
     */
    _unwind_helper(std::function<void()> unwind) : _unwind(unwind) {}

    /**
     * @brief Destroy the unwind helper object
     *
     */
    ~_unwind_helper() { _unwind(); }

  private:
    std::function<void()> _unwind;
};
