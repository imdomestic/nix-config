const assert = require('node:assert/strict');
const fs = require('node:fs');
const vscode = require('vscode');
const path = require('node:path');
const root = path.dirname(__dirname);
const results = [];
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(test, label) {
  for (let i = 0; i < 100; i++) {
    if (await test()) return;
    await sleep(100);
  }
  throw new Error(`Timed out: ${label}`);
}
// Run by scripts/test-vscode-neovim.sh in a temporary VS Code profile.
exports.run = async function () {
  try {
    const defaults = vscode.extensions.getExtension('hank.nixvim-defaults');
    assert(defaults, 'defaults extension registered');
    const manifest = defaults.packageJSON;
    assert.equal(fs.readFileSync(`${defaults.extensionPath}/snippets/rust.json`, 'utf8').includes('Rust CP Template'), true);
    const conf = vscode.workspace.getConfiguration();
    const key = `vscode-neovim.neovimExecutablePaths.${process.platform}`;
    assert.equal(conf.get(key), manifest.contributes.configurationDefaults[key]);
    assert.equal(conf.inspect('editor.cursorSurroundingLines').defaultValue, 10);
    await conf.update('editor.cursorSurroundingLines', 3, vscode.ConfigurationTarget.Global);
    await until(() => vscode.workspace.getConfiguration().get('editor.cursorSurroundingLines') === 3, 'user setting override');
    assert.equal(conf.inspect('editor.cursorSurroundingLines').defaultValue, 10);
    await conf.update('editor.cursorSurroundingLines', undefined, vscode.ConfigurationTarget.Global);
    await until(() => vscode.workspace.getConfiguration().get('editor.cursorSurroundingLines') === 10, 'reset user setting');
    results.push('extension defaults < GUI/user override; reset restores Nix default');

    const commands = new Set(await vscode.commands.getCommands(false));
    for (const binding of manifest.contributes.keybindings) {
      assert(commands.has(binding.command), `VS Code command exists: ${binding.command}`);
    }
    const ext = vscode.extensions.getExtension('asvetliakov.vscode-neovim');
    await ext.activate();
    await until(async () => (await vscode.commands.getCommands(false)).includes('_getNeovimClient'), 'Neovim client');
    const client = await vscode.commands.executeCommand('_getNeovimClient');
    await until(async () => (await client.executeLua('return vim.g.vscode', [])) === 1, 'Neovim startup');
    await sleep(1500);
    const commandsInMappings = await client.executeLua(`
      local commands = {}
      local code = require('vscode')
      local old_action = code.action
      code.action = function(name) table.insert(commands, name) end
      for _, map in ipairs(vim.api.nvim_get_keymap('n')) do
        if type(map.callback) == 'function' and map.desc and map.lhs ~= ' lH' then
          local info = debug.getinfo(map.callback, 'S')
          if info and info.source:find('init.lua', 1, true) and not map.desc:find('Flash') then
            map.callback()
          end
        end
      end
      code.action = old_action
      return commands
    `, []);
    assert(commandsInMappings.length >= 40, 'bridge mappings were inspected');
    for (const command of commandsInMappings) assert(commands.has(command), `mapped command exists: ${command}`);
    results.push(`${commandsInMappings.length} mapped VS Code commands registered`);
    const state = await client.executeLua(`return {
      leader = vim.g.mapleader, timeout = vim.o.timeoutlen,
      clipboard = vim.g.clipboard and vim.g.clipboard.name,
      surround = package.loaded['mini.surround'] ~= nil,
      flash = package.loaded['flash'] ~= nil,
      lsp = #vim.lsp.get_clients(),
      no_snacks = package.loaded['snacks'] == nil,
      no_blink = package.loaded['blink.cmp'] == nil,
      no_noice = package.loaded['noice'] == nil,
      errors = vim.v.errmsg,
    }`, []);
    results.push(state);
    assert.equal(state.leader, ' ');
    assert.equal(state.timeout, 300);
    assert.equal(state.clipboard, 'VSCodeClipboard');
    for (const k of ['surround','flash','no_snacks','no_blink','no_noice']) assert(state[k], k);
    assert.equal(state.lsp, 0);
    assert.equal(state.errors, '');

    const a = await vscode.workspace.openTextDocument(vscode.Uri.file(`${root}/workspace/a.js`));
    const b = await vscode.workspace.openTextDocument(vscode.Uri.file(`${root}/workspace/b.txt`));
    const show = async doc => {
      await vscode.window.showTextDocument(doc, {preview:false});
      await until(async () => (await client.executeLua('return vim.api.nvim_buf_get_name(0)', [])).endsWith(doc.uri.fsPath), `sync ${doc.fileName}`);
      await sleep(200);
    };
    const send = async keys => {
      await vscode.commands.executeCommand('vscode-neovim.send', keys);
      await sleep(600);
    };
    await show(a); await show(b);
    await send('[b');
    await until(() => vscode.window.activeTextEditor?.document === a, '[b previous editor');
    await send(']b');
    await until(() => vscode.window.activeTextEditor?.document === b, ']b next editor');
    results.push('[b / ]b switch real VS Code tabs');

    await send('<C-w>v');
    await until(() => vscode.window.tabGroups.all.length === 2, 'split editor');
    await send('<C-h>');
    await until(() => vscode.window.activeTextEditor?.viewColumn === 1, 'focus left');
    await send('<C-l>');
    await until(() => vscode.window.activeTextEditor?.viewColumn === 2, 'focus right');
    results.push('Ctrl-w v and Ctrl-h/l navigate real editor groups');
    await send('<C-w>s');
    await until(() => vscode.window.tabGroups.all.length === 3, 'split below');
    await send('<C-k>');
    await until(() => vscode.window.activeTextEditor?.viewColumn === 2, 'focus above');
    await send('<C-j>');
    await until(() => vscode.window.activeTextEditor?.viewColumn === 3, 'focus below');
    results.push('Ctrl-w s and Ctrl-j/k navigate vertical editor groups');

    await send('gg0saiw)');
    await until(() => b.getText().startsWith('(alpha) beta'), 'surround');
    results.push('mini.surround modifies the VS Code document');
    await send('u');
    await until(() => b.getText() === 'alpha beta\n', 'undo surround');

    await show(a);
    const parsed = await client.executeLua(`local p = vim.treesitter.get_parser(0, 'javascript'); return p:parse()[1]:root():type()`, []);
    assert.equal(parsed, 'program');
    await send('gg0daf');
    await until(() => !a.getText().includes('function alpha') && a.getText().includes('function beta'), 'Tree-sitter daf');
    results.push('Tree-sitter daf deletes only the selected function in VS Code');
    await send('u');

    await send(' lH');
    await until(() => vscode.workspace.getConfiguration().get('editor.inlayHints.enabled') === 'on', 'toggle inlay hints on');
    await send(' lH');
    await until(() => vscode.workspace.getConfiguration().get('editor.inlayHints.enabled') === 'off', 'toggle inlay hints off');
    results.push('leader lH toggles the user setting');

    await send(' ff');
    await sleep(300);
    await vscode.commands.executeCommand('workbench.action.closeQuickOpen');
    results.push('leader ff opens Quick Open without a Lua error');
    assert.equal(await client.executeLua('return vim.v.errmsg', []), '');
    fs.writeFileSync(`${root}/result.json`, JSON.stringify({ok:true,results},null,2));
  } catch (error) {
    fs.writeFileSync(`${root}/result.json`, JSON.stringify({ok:false,results,error:String(error),stack:error.stack},null,2));
    throw error;
  }
};
