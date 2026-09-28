"""UI regression checks; requires Python's pynvim package and Neovim 0.12+."""
import argparse
import json
from pathlib import Path
import tempfile

import pynvim

parser = argparse.ArgumentParser()
parser.add_argument('--nvim', default='nvim')
parser.add_argument('--init', default='NONE')
parser.add_argument('--capture-json')
parser.add_argument('--capture-explorer-json')
args = parser.parse_args()
n = pynvim.attach('child', argv=[args.nvim, '--embed', '--headless', '-u', args.init, '-i', 'NONE'])
n.ui_attach(120,32, rgb=True, ext_linegrid=True)

def lua(code, *values):
    return n.exec_lua(code, *values)

def settle():
    lua('vim.wait(360)')
    n.command('redraw!')

def row(number):
    return lua('local t={} for c=1,vim.o.columns do t[c]=vim.fn.screenstring(...,c) end return table.concat(t)', number)

def ordinary_windows():
    return lua('local t={} for _,w in ipairs(vim.api.nvim_tabpage_list_wins(0)) do if vim.api.nvim_win_get_config(w).relative=="" then t[#t+1]=w end end return t')

def capture(path):
    cells=lua('local rows={} for r=1,12 do rows[r]={} for c=1,vim.o.columns do rows[r][c]={vim.fn.screenstring(r,c),vim.fn.screenattr(r,c)} end end return rows')
    attrs={0:{}}
    for msg in n._session._pending_messages:
        if msg.type=='notification' and msg.name=='redraw':
            for event in msg.args:
                if event[0]=='hl_attr_define':
                    for entry in event[1:]:attrs[entry[0]]=entry[1]
    Path(path).write_text(json.dumps({'cells':cells,'attrs':attrs}))

try:
    if args.init != 'NONE':
        assert lua("return package.loaded['hank-tabline'] ~= nil and _G.MiniTabline == nil"), n.command_output('messages')
    lua('vim.opt.rtp:prepend(...)', str(Path(__file__).parent))
    lua('''
      vim.o.laststatus=3; vim.o.hidden=true; vim.o.mouse='a'; vim.o.cmdheight=1
      if not package.loaded['hank-tabline'] then
        require('hank-tabline').setup({palette=function() return {
          crust='#171c1f',base='#1e2528',green='#cbe3b3',overlay2='#839e9a',overlay0='#58686d'
        } end})
      end
    ''')
    buffers=[]
    with tempfile.TemporaryDirectory(prefix='hank-tabline-') as directory:
        for name in ('flake.nix','Justfile','home-utils.nix'):
            b=n.api.create_buf(True,False)
            n.api.buf_set_name(b,str(Path(directory)/name))
            n.api.buf_set_lines(b,0,-1,False,['first line is visible','','last line'])
            n.api.set_option_value('modified',False,{'buf':b})
            n.api.set_current_buf(b)
            buffers.append(b.number)
        # Drop the original unnamed buffer from the list, as :edit normally does.
        lua('if vim.api.nvim_buf_is_valid(1) and vim.api.nvim_buf_get_name(1)=="" then vim.bo[1].buflisted=false end')
        settle()
        assert len(ordinary_windows())==1
        assert row(1).startswith(' flake.nix  Justfile  home-utils.nix '), row(1)
        assert len(row(2))==120 and set(row(2)) <= set('━╸╺'), row(2)
        assert 'first line is visible' in row(3),row(3)
        selected=n.api.get_hl(0,{'name':'HankTablineSelected','link':False})
        assert selected['bg']==int('cbe3b3',16) and selected['bold']
        print('PASS: two rows, Evergarden palette, file content starts below the track')
        original=n.api.get_current_win()
        n.command('wincmd k');settle()
        assert n.api.get_current_win()==original
        for command in ('vsplit','split'):
            n.command(command);settle()
        assert len(ordinary_windows())==3
        for w in ordinary_windows():
            pos=n.api.win_get_position(w)
            assert n.api.get_option_value('winbar',{'win':w})==(' ' if pos[0]==1 else '')
        n.command('only');settle();assert len(ordinary_windows())==1
        n.command('tabnew');settle();assert len(ordinary_windows())==1
        n.command('tabclose');settle();assert len(ordinary_windows())==1
        print('PASS: split navigation, :only, and tabpage lifecycle add no ordinary windows')
        # Actual mouse input exercises the native tab callback and the second-row map.
        for screenrow, col, expected in ((0,3,buffers[0]),(1,14,buffers[1])):
            n.api.input_mouse('left','press','',0,screenrow,col)
            n.api.input_mouse('left','release','',0,screenrow,col)
            settle();assert n.api.get_current_buf().number==expected,(screenrow,n.api.get_current_buf().number)
        lua('vim.api.nvim_buf_set_lines(0,-1,-1,false,{"modified"})');settle()
        assert 'Justfile ●' in row(1)
        lua('vim.bo.modified=false');settle()
        assert '●' not in row(1)
        print('PASS: both rows are clickable and modified indicators update')
        # Narrow view, wide characters, literal percent signs and duplicate basenames.
        for name in ('a/shared.txt','b/shared.txt','目录/宽字符%very-long-name.txt'):
            b=n.api.create_buf(True,False)
            n.api.buf_set_name(b,str(Path(directory)/name))
            n.api.set_current_buf(b)
        n.ui_try_resize(35,12);settle()
        assert 'Error' not in n.command_output('messages'),n.command_output('messages')
        assert '%' in row(1),row(1)
        assert len(row(2))==35
        n.ui_try_resize(120,32);settle()
        n.api.set_current_buf(buffers[-1]);settle()
        print('PASS: overflow, Unicode and statusline escaping')
        if lua('return _G.Snacks ~= nil'):
            lua('for _,b in ipairs(vim.api.nvim_list_bufs()) do if vim.bo[b].buftype=="" then vim.bo[b].buflisted=vim.tbl_contains(...,b) end end',buffers)
            lua('_G.hank_test_explorer=Snacks.picker.explorer(); vim.wait(300)');settle()
            def check_sidebar():
                left=lua('return vim.api.nvim_win_get_width(hank_test_explorer.layout.root.win)+1')
                position=lua('return vim.api.nvim_win_get_position(hank_test_explorer.input.win.win)')
                assert position==[0,0],position
                assert 'Explorer' in row(1)[:left],row(1)
                assert row(1)[left:].startswith(' flake.nix  Justfile '),row(1)
                assert set(row(2)[left:]) <= set('━╸╺'),row(2)
                assert 'first line is visible' in row(3)[left:],row(3)
                assert lua('local w=hank_test_explorer.list.win.win; return vim.api.nvim_win_get_position(w)[1]+vim.api.nvim_win_get_height(w)')==30
                assert len(ordinary_windows())==2
                return left
            left=check_sidebar()
            lua('hank_test_explorer.layout:update()');settle()
            check_sidebar()
            for screenrow,col,expected in ((0,3,buffers[0]),(1,14,buffers[1])):
                n.api.input_mouse('left','press','',0,screenrow,left+col)
                n.api.input_mouse('left','release','',0,screenrow,left+col)
                settle();assert n.api.get_current_buf().number==expected
            lua('vim.api.nvim_win_set_width(hank_test_explorer.layout.root.win,40)');settle()
            assert check_sidebar()==41
            n.ui_try_resize(100,32);settle();check_sidebar()
            n.ui_try_resize(120,32);settle();check_sidebar()
            n.command('tabnew');settle()
            assert row(1).startswith(' flake.nix'),row(1)
            n.command('tabclose');settle();check_sidebar()
            for expression in ('Snacks.picker.files()','Snacks.lazygit({configure=false,interactive=false})'):
                lua('_G.hank_test_float='+expression);settle()
                assert not lua('local x={} for _,w in ipairs(vim.api.nvim_list_wins()) do if vim.bo[vim.api.nvim_win_get_buf(w)].filetype=="snacks_win_backdrop" then x[#x+1]=w end end return next(x)~=nil')
                lua('hank_test_float:close()');settle()
                check_sidebar()
            if args.capture_explorer_json:capture(args.capture_explorer_json)
            lua('hank_test_explorer:close()');settle()
            assert row(1).startswith(' flake.nix') and set(row(2)) <= set('━╸╺')
            assert len(ordinary_windows())==1
            assert 'Error' not in n.command_output('messages'),n.command_output('messages')
            print('PASS: top-left Explorer, offset clicks, sidebar/UI resize, tabpages, close, Picker and LazyGit')
        if args.capture_json:
            # Keep only the three demonstration buffers for a readable preview.
            lua('for _,b in ipairs(vim.api.nvim_list_bufs()) do if vim.bo[b].buftype=="" then vim.bo[b].buflisted=vim.tbl_contains(...,b) end end',buffers)
            settle()
            capture(args.capture_json)
        lua('for _,b in ipairs(vim.api.nvim_list_bufs()) do vim.bo[b].modified=false end')
        try:
            n.command('quit')
        except EOFError:
            print('PASS: :quit exits the last editor; the decorative float does not keep Nvim alive')
        else:
            raise AssertionError('decorative window prevented :quit')
finally:
    try:n.command('qa!')
    except (EOFError,OSError):pass
