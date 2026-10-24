export const initialGmailAnalysisState = Object.freeze({
  target: null,
  result: null,
  busy: false,
  error: '',
});

export function gmailAnalysisReducer(state, action) {
  switch (action.type) {
    case 'confirm':
      return { target: action.message, result: null, busy: false, error: '' };
    case 'cancel':
    case 'clear':
      return initialGmailAnalysisState;
    case 'start':
      return { ...state, target: action.message, result: null, busy: true, error: '' };
    case 'success':
      return { target: null, result: action.result, busy: false, error: '' };
    case 'failure':
      return { target: null, result: null, busy: false, error: action.message };
    default:
      return state;
  }
}
