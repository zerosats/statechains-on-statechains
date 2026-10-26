import test from 'node:test';
import assert from 'node:assert/strict';
import { initialModel, applyEvent, applyShellError, beginAction, endAction } from '../ui/model.js';

test('replies decide the outcome while background errors cannot clear a reply', () => {
  const model = initialModel();
  beginAction(model, 'publicSend');
  assert.equal(model.progress, 'Working…');
  applyEvent(model, { error: 'Spark regtest unreachable' }, false);
  assert.equal(model.error, 'Spark regtest unreachable');
  applyEvent(model, { id: 'ui-1' }, true);
  assert.equal(model.error, null);
  applyEvent(model, { progress: 'Proving…' }, false);
  assert.equal(model.progress, 'Proving…');
  endAction(model);
  assert.deepEqual([model.busy, model.progress], [false, '']);
  beginAction(model, 'refresh');
  assert.equal(model.progress, '');
  applyShellError(model, 'Wallet stopped. Reopen Zark.');
  assert.deepEqual([model.busy, model.error], [false, 'Wallet stopped. Reopen Zark.']);
});
