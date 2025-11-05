hi clear
set nocp
set encoding=utf-8
set guicursor=n-v-c-i:block-Cursor
let mapleader=" "
exec "nohlsearch"

syntax on
filetype plugin indent on

set number
set mouse=a
set showcmd
set path+=**
set wildmenu
set number
set hlsearch
set title
set showcmd
set showmode
set termguicolors

set incsearch
set ignorecase
set smartcase
set cursorline

set autoindent
set tabstop=4
set softtabstop=4
set shiftwidth=4
set expandtab
set scrolloff=5
set laststatus=2

" mappings
noremap J 5gj
noremap K 5gk
noremap H 5h
noremap L 5l

nmap ; :
nmap j gj
nmap k gk

map <C-l> <C-w>l
map <C-h> <C-w>h
map <C-j> <C-w>j
map <C-k> <C-w>k

map <LEADER>n :tabnew<CR>
map <LEADER>c :tabclose<CR>
map <LEADER>w :w<CR>
map <LEADER>q :q<CR>
map <LEADER>Q :q!<CR>

map <LEADER>uw :set wrap!<CR>
map <LEADER>ui4 :set tabstop=4<CR>:set softtabstop=4<CR>:set shiftwidth=4<CR>
map <LEADER>ui2 :set tabstop=2<CR>:set softtabstop=2<CR>:set shiftwidth=2<CR>

map [b :tabnext<CR>
map ]b :tabprev<CR>

set guicursor=n-v-c:block,i:ver25

nnoremap <leader>e :NERDTreeToggle<CR>
map s <Plug>(easymotion-prefix)
map <ENTER> <Plug>(wildfire-fuel)
vmap <BS> <Plug>(wildfire-water)

let g:lightline = { 'colorscheme': 'iceberg' }

set background=dark
silent! colorscheme iceberg

set showtabline=2

function! SpawnBufferLine()
  let s = ' '

  " Get the list of buffers. Use bufexists() to include hidden buffers
  let bufferNums = filter(range(1, bufnr('$')), 'buflisted(v:val)')
  " Making a buffer list on the left side
  for i in bufferNums
    " Highlight with yellow if it's the current buffer
    let s .= (i == bufnr()) ? ('%#TabLineSel#') : ('%#TabLine#')
    let s .= i . ' '  " Append the buffer number
    if bufname(i) == ''
      let s .= '[NEW]'  " Give a name to a new buffer
    endif
    if getbufvar(i, "&modifiable")
      let s .= fnamemodify(bufname(i), ':t')  " Append the file name
      " let s .= pathshorten(bufname(i))  " Use this if you want a trimmed path
      " If the buffer is modified, add + and separator. Else, add separator
      let s .= (getbufvar(i, "&modified")) ? (' [+] | ') : (' | ')
    else
      let s .= fnamemodify(bufname(i), ':t') . ' [RO] | '  " Add read only flag
    endif
  endfor
  let s .= '%#TabLineFill#%T'  " Reset highlight

  let s .= '%=' " Spacer

  " Making a tab list on the right side
  for i in range(1, tabpagenr('$'))  " Loop through the number of tabs
    " Highlight with yellow if it's the current tab
    let s .= (i == tabpagenr()) ? ('%#TabLineSel#') : ('%#TabLine#')
    let s .= '%' . i . 'T '  " set the tab page number (for mouse clicks)
    let s .= i . ''          " set page number string
  endfor
  let s .= '%#TabLineFill#%T'  " Reset highlight

  " Close button on the right if there are multiple tabs
  if tabpagenr('$') > 1
    let s .= '%999X X'
  endif
  return s
endfunction

set tabline=%!SpawnBufferLine()  " Assign the tabline
