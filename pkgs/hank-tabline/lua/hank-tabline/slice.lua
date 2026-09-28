-- Slice by screen cells, retaining composing characters and padding split wide glyphs.
return function(text, from, width)
  local out, col = {}, 0
  for i = 0, vim.fn.strchars(text, true) - 1 do
    local char = vim.fn.strcharpart(text, i, 1, true)
    local w = vim.fn.strdisplaywidth(char)
    if col >= from and col + w <= from + width then
      out[#out + 1] = char
    elseif col < from + width and col + w > from then
      out[#out + 1] = string.rep(' ', math.min(col + w, from + width) - math.max(col, from))
    end
    col = col + w
    if col >= from + width then break end
  end
  return table.concat(out)
end
