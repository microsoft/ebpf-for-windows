'use strict';

import { MONITORING_IN_PROGRESS } from 'actions/monitorActions';

const getDefaultState = () => {
  const defaultState = {
    monitoringInProgress: true
  };
  return defaultState;
};

const monitorReducer = (state = getDefaultState(), action) => {
  switch (action.type) {
    case MONITORING_IN_PROGRESS:
      return {
        ...state,
        monitoringInProgress: true,
        error: null
      };
    default:
      return state;
  }
};

export default monitorReducer;
