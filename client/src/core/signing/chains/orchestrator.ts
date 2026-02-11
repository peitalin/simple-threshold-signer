import { signDelegateAction as signNearDelegateActionHandler } from './near/handlers/signDelegateAction';
import { signNep413Message as signNearNep413MessageHandler } from './near/handlers/signNep413Message';
import { signTransactionsWithActions as signNearTransactionsWithActionsHandler } from './near/handlers/signTransactionsWithActions';
import { signTempoWithSecureConfirm as signTempoWithSecureConfirmHandler } from './tempo/handlers/signTempoWithSecureConfirm';

export async function signNearTransactionsWithActions(
  args: Parameters<typeof signNearTransactionsWithActionsHandler>[0],
): Promise<Awaited<ReturnType<typeof signNearTransactionsWithActionsHandler>>> {
  return await signNearTransactionsWithActionsHandler(args);
}

export async function signNearDelegateAction(
  args: Parameters<typeof signNearDelegateActionHandler>[0],
): Promise<Awaited<ReturnType<typeof signNearDelegateActionHandler>>> {
  return await signNearDelegateActionHandler(args);
}

export async function signNearNep413Message(
  args: Parameters<typeof signNearNep413MessageHandler>[0],
): Promise<Awaited<ReturnType<typeof signNearNep413MessageHandler>>> {
  return await signNearNep413MessageHandler(args);
}

export async function signTempoWithSecureConfirm(
  args: Parameters<typeof signTempoWithSecureConfirmHandler>[0],
): Promise<Awaited<ReturnType<typeof signTempoWithSecureConfirmHandler>>> {
  return await signTempoWithSecureConfirmHandler(args);
}
