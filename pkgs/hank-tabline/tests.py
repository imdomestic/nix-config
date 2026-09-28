"""UI regression checks; requires Python's pynvim package and Neovim 0.12+."""
import argparse
import json
from pathlib import Path
import tempfile

import pynvim

parser = argparse.ArgumentParser()
parser.add_argument('--nvim', default='nvim')
parser.add_argument('--init', default='NONE')
parser.add_argument('--underline', action='store_true')
parser.add_argument('--project', action='store_true')
parser.add_argument('--no-animate', action='store_true')
parser.add_argument('--capture-json')
parser.add_argument('--capture-explorer-json')
args = parser.parse_args()
header_rows = 2 if args.underline else 1
bare = args.init == 'NONE'
here = Path(__file__).parent
n = pynvim.attach('child', argv=[args.nvim, '--embed', '--headless', '-u', args.init, '-i', 'NONE'])
n.ui_attach(120,32, rgb=True, ext_linegrid=True)

def lua(code, *values):
    return n.exec_lua(code, *values)

def settle():
    lua('vim.wait(360)')
    n.command('redraw!')

def row(number):
    return lua('local t={} for c=1,vim.o.columns do t[c]=vim.fn.screenstring(...,c) end return table.concat(t)', number)

def width(text):
    return lua('return vim.fn.strdisplaywidth(...)', text)

def click(screenrow, col):
    n.api.input_mouse('left','press','',0,screenrow,col)
    n.api.input_mouse('left','release','',0,screenrow,col)
    settle()

def ordinary_windows():
    return lua('local t={} for _,w in ipairs(vim.api.nvim_tabpage_list_wins(0)) do if vim.api.nvim_win_get_config(w).relative=="" then t[#t+1]=w end end return t')

def filetypes():
    return lua('local t={} for _,w in ipairs(vim.api.nvim_tabpage_list_wins(0)) do if vim.api.nvim_win_get_config(w).relative=="" then t[#t+1]=vim.bo[vim.api.nvim_win_get_buf(w)].filetype end end return t')

def lead():
    # Everything left of the buffer tabs: the optional project label, then the panel icons.
    return lua('''
      local project, parts = ..., {}
      if project then parts[#parts+1] = require('hank-tabline.project').items({columns=vim.o.columns})[1].text end
      local ok, panels = pcall(require, 'hank-panels')
      if ok then for _, item in ipairs(panels.section('left').items()) do parts[#parts+1] = item.text end end
      return table.concat(parts)
    ''', args.project)

def panel_col(id, side='left'):
    # Screen column (0-based) of a panel's glyph.
    return lua('''
      local id, side, project = ...
      local items, col = require('hank-panels').section(side).items(), 0
      if side == 'right' then
        for _, item in ipairs(items) do col = col + vim.fn.strdisplaywidth(item.text) end
        col = vim.o.columns - col
      elseif project then
        col = vim.fn.strdisplaywidth(require('hank-tabline.project').items({columns=vim.o.columns})[1].text)
      end
      for _, item in ipairs(items) do
        if item.id == id then return col + 1 end
        col = col + vim.fn.strdisplaywidth(item.text)
      end
    ''', id, side, args.project)

def lit():
    # Rail columns (1-based) drawn in the accent colour.
    return lua('local t={} for c=1,vim.o.columns do if vim.fn.screenattr(2,c)~=... then t[#t+1]=c end end return t',track_attr)

def check_track():
    bars=lua('local t={} for _,w in ipairs(vim.api.nvim_tabpage_list_wins(0)) do if vim.bo[vim.api.nvim_win_get_buf(w)].filetype=="hank_tabline" then t[#t+1]=w end end return t')
    if args.underline:
        assert len(bars)==1 and set(row(2)) <= set('━╸╺'),row(2)
    else:
        assert not bars,bars

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
    if not bare:
        assert lua("return package.loaded['hank-tabline'] ~= nil and _G.MiniTabline == nil"), n.command_output('messages')
    lua('vim.opt.rtp:prepend(...)', str(here))
    lua('vim.opt.rtp:prepend(...)', str(here.parent/'hank-panels'))
    lua('''
      local underline, project, animate = ...
      vim.o.laststatus=3; vim.o.hidden=true; vim.o.mouse='a'; vim.o.cmdheight=1
      if not package.loaded['hank-tabline'] then
        local panels, a = require('hank-panels'), require('hank-panels.adapters')
        local function fake(ft, command)
          return function()
            vim.cmd(command); vim.bo.buftype='nofile'; vim.bo.bufhidden='wipe'; vim.bo.filetype=ft
          end
        end
        panels.setup({panels={
          a.window({id='tree',icon=0xf024b,icon_inactive=0xf0256,ft='faketree',open=fake('faketree','topleft 20vnew')}),
          a.window({id='outline',icon=0xf0645,icon_inactive=0xf13d2,ft='fakeoutline',open=fake('fakeoutline','topleft 20vnew')}),
          a.window({id='info',side='right',icon=0xf02fc,icon_inactive=0xf02fd,ft='fakeinfo',open=fake('fakeinfo','botright 30vnew')}),
        }})
        require('hank-tabline').setup({underline=underline,project=project,animate=animate,
          sections={left={panels.section('left')},right={panels.section('right')}},
          palette=function() return {
            crust='#171c1f',base='#1e2528',green='#cbe3b3',overlay2='#839e9a',overlay0='#58686d'
          } end})
      end
    ''',args.underline,args.project,not args.no_animate)
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
        prefix=lead()
        prefix_width=width(prefix)
        project_label='  nix-config '
        assert prefix.startswith(project_label) if args.project else '' not in row(1),row(1)
        assert row(1).startswith(prefix+' flake.nix  Justfile  home-utils.nix '),row(1)
        if bare:assert row(1).endswith(' \U000f02fd '),row(1)
        check_track()
        # No panel is open yet, so the first cell of the rail is plain track.
        track_attr=lua('return vim.fn.screenattr(2,1)')
        assert 'first line is visible' in row(header_rows+1),row(header_rows+1)
        selected=n.api.get_hl(0,{'name':'HankTablineSelected','link':False})
        assert selected['bg']==int('cbe3b3',16) and selected['bold']
        print('PASS: configured header height, optional project label, panel icons, Evergarden palette, unobstructed first file line')
        original=n.api.get_current_win()
        n.command('wincmd k');settle()
        assert n.api.get_current_win()==original
        for command in ('vsplit','split'):
            n.command(command);settle()
        assert len(ordinary_windows())==3
        for w in ordinary_windows():
            pos=n.api.win_get_position(w)
            assert n.api.get_option_value('winbar',{'win':w})==(' ' if args.underline and pos[0]==1 else '')
        n.command('only');settle();assert len(ordinary_windows())==1
        n.command('tabnew');settle();assert len(ordinary_windows())==1
        n.command('tabclose');settle();assert len(ordinary_windows())==1
        print('PASS: split navigation, :only, and tabpage lifecycle add no ordinary windows')
        # Actual mouse input exercises the native tab callback and the second-row map.
        for screenrow, col, expected in ((0,3,buffers[0]),(header_rows-1,14,buffers[1])):
            click(screenrow,prefix_width+col)
            assert n.api.get_current_buf().number==expected,(screenrow,n.api.get_current_buf().number)
        lua('vim.api.nvim_buf_set_lines(0,-1,-1,false,{"modified"})');settle()
        assert 'Justfile ●' in row(1)
        lua('vim.bo.modified=false');settle()
        assert '●' not in row(1)
        assert row(1)[:prefix_width]==prefix,row(1)
        # The project label and the empty stretch before the right-hand icons are inert.
        inert=[2] if args.project else []
        inert.append(100)
        for screenrow in range(header_rows):
            for col in inert:
                before=n.api.get_current_buf().number
                click(screenrow,col)
                assert n.api.get_current_buf().number==before and len(ordinary_windows())==1
        if args.project:
            original_cwd=lua('return vim.fn.getcwd(-1,0)')
            project=Path(directory)/'项目%name'
            project.mkdir()
            lua('vim.cmd.tcd({args={vim.fn.fnameescape(...)},mods={silent=true}})',str(project));settle()
            assert '项目%name' in row(1),row(1)
            lua('vim.cmd.tcd({args={vim.fn.fnameescape(...)},mods={silent=true}})',original_cwd);settle()
            assert row(1)[:prefix_width]==prefix
        print('PASS: fixed lead, directory changes, inert gaps, offset clicks and modified indicators')
        if args.underline:
            n.command(f'buffer {buffers[0]}');settle();first=lit()
            n.command(f'buffer {buffers[2]}');settle();last=lit()
            assert first and last and first!=last,(first,last)
            n.command(f'buffer {buffers[0]}');settle()
            n.command(f'buffer {buffers[2]}');lua('vim.wait(150)');n.command('redraw!')
            midway=lit()
            assert midway==last if args.no_animate else midway not in (first,last),(first,midway,last)
            settle();assert lit()==last
            print('PASS: rail', 'jumps without animation' if args.no_animate else 'glides between tabs')
        if bare:
            tree,outline,info=panel_col('tree'),panel_col('outline'),panel_col('info','right')
            tabs=row(1)[prefix_width:prefix_width+30]
            click(0,tree)
            assert 'faketree' in filetypes() and row(1)[tree]=='\U000f024b',(filetypes(),row(1))
            assert row(1)[prefix_width:prefix_width+30]==tabs,row(1)
            if args.underline:assert tree+1 in lit(),lit()
            click(0,outline)
            assert 'fakeoutline' in filetypes() and 'faketree' not in filetypes(),filetypes()
            assert row(1)[tree]=='\U000f0256' and row(1)[outline]=='\U000f0645',row(1)
            click(0,info)
            assert {'fakeoutline','fakeinfo'} <= set(filetypes()),filetypes()
            click(header_rows-1,outline)
            assert 'fakeoutline' not in filetypes() and 'fakeinfo' in filetypes(),filetypes()
            lua("require('hank-panels').toggle('info')");settle()
            assert len(ordinary_windows())==1 and row(1)[prefix_width:prefix_width+30]==tabs
            check_track()
            print('PASS: panel icons toggle, one panel per side, both sides, header clicks and rail clicks')
        # Narrow view, wide characters, literal percent signs and duplicate basenames.
        for name in ('a/shared.txt','b/shared.txt','目录/宽字符%very-long-name.txt'):
            b=n.api.create_buf(True,False)
            n.api.buf_set_name(b,str(Path(directory)/name))
            n.api.set_current_buf(b)
        n.ui_try_resize(35,12);settle()
        assert 'Error' not in n.command_output('messages'),n.command_output('messages')
        assert '%' in row(1),row(1)
        assert len(row(2))==35
        if args.underline:assert lua('return vim.fn.screenattr(2,1)')==track_attr
        check_track()
        n.ui_try_resize(120,32);settle()
        n.api.set_current_buf(buffers[-1]);settle()
        print('PASS: overflow, Unicode and statusline escaping')
        if lua('return _G.Snacks ~= nil'):
            lua('for _,b in ipairs(vim.api.nvim_list_bufs()) do if vim.bo[b].buftype=="" then vim.bo[b].buflisted=vim.tbl_contains(...,b) end end',buffers)
            lua('_G.hank_test_explorer=Snacks.picker.explorer(); vim.wait(300)');settle()
            def check_sidebar():
                left=lua('return vim.api.nvim_win_get_width(hank_test_explorer.layout.root.win)+1')
                position=lua('return vim.api.nvim_win_get_position(hank_test_explorer.input.win.win)')
                assert position==[header_rows,0],position
                assert 'Explorer' in row(header_rows+1)[:left],row(header_rows+1)
                assert row(1)[:prefix_width]==lead(),row(1)
                assert row(1)[prefix_width:].startswith(' flake.nix  Justfile '),row(1)
                check_track()
                assert 'first line is visible' in row(header_rows+1)[left:],row(header_rows+1)
                assert lua('local w=hank_test_explorer.list.win.win; return vim.api.nvim_win_get_position(w)[1]+vim.api.nvim_win_get_height(w)')==30
                assert len(ordinary_windows())==2
                return left
            left=check_sidebar()
            assert lua("return require('hank-panels').is_open('explorer')")
            lua('hank_test_explorer.layout:update()');settle()
            check_sidebar()
            for screenrow,col,expected in ((0,3,buffers[0]),(header_rows-1,14,buffers[1])):
                click(screenrow,prefix_width+col)
                assert n.api.get_current_buf().number==expected
            lua('vim.api.nvim_win_set_width(hank_test_explorer.layout.root.win,40)');settle()
            assert check_sidebar()==41
            n.ui_try_resize(100,32);settle();check_sidebar()
            n.ui_try_resize(120,32);settle();check_sidebar()
            n.command('tabnew');settle()
            assert row(1)[prefix_width:].startswith(' flake.nix'),row(1)
            n.command('tabclose');settle();check_sidebar()
            for expression in ('Snacks.picker.files()','Snacks.lazygit({configure=false,interactive=false})'):
                lua('_G.hank_test_float='+expression);settle()
                assert not lua('local x={} for _,w in ipairs(vim.api.nvim_list_wins()) do if vim.bo[vim.api.nvim_win_get_buf(w)].filetype=="snacks_win_backdrop" then x[#x+1]=w end end return next(x)~=nil')
                lua('hank_test_float:close()');settle()
                check_sidebar()
            if args.capture_explorer_json:capture(args.capture_explorer_json)
            lua('hank_test_explorer:close()');settle()
            assert row(1)[prefix_width:].startswith(' flake.nix')
            assert len(ordinary_windows())==1
            check_track()
            assert 'Error' not in n.command_output('messages'),n.command_output('messages')
            print('PASS: full-width header above Explorer, sidebar-independent lead, resize, tabpages, close, Picker and LazyGit')
            if lua("return package.loaded['hank-panels'] ~= nil and require('hank-panels').get('git') ~= nil"):
                is_open="return require('hank-panels').is_open(...)"
                click(0,panel_col('explorer'));lua('vim.wait(300)');settle()
                assert lua(is_open,'explorer')
                click(0,panel_col('git'));lua('vim.wait(300)');settle()
                assert lua(is_open,'git') and not lua(is_open,'explorer')
                assert row(1)[:prefix_width]==lead() and row(1)[prefix_width:].startswith(' flake.nix'),row(1)
                if args.underline:
                    assert lua('return vim.wo[vim.fn.win_getid(1)].winbar')==' '
                click(0,panel_col('git'));settle()
                assert not lua(is_open,'git') and len(ordinary_windows())==1
                assert 'Error' not in n.command_output('messages'),n.command_output('messages')
                print('PASS: configured panels switch Explorer and Git from the header')
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
