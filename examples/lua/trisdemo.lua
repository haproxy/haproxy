-- Example game of falling pieces for HAProxy CLI/Applet
local board_width = 10
local board_height = 20
local game_name = "Lua Tris Demo"

-- Shapes with IDs for color mapping
local pieces = {
    {id = 1, shape = {{1,1,1,1}}},        -- I (Cyan)
    {id = 2, shape = {{1,1},{1,1}}},      -- O (Yellow)
    {id = 3, shape = {{0,1,0},{1,1,1}}},  -- T (Purple)
    {id = 4, shape = {{0,1,1},{1,1,0}}},  -- S (Green)
    {id = 5, shape = {{1,1,0},{0,1,1}}},  -- Z (Red)
    {id = 6, shape = {{1,0,0},{1,1,1}}},  -- J (Blue)
    {id = 7, shape = {{0,0,1},{1,1,1}}}   -- L (Orange)
}

-- ANSI escape codes
local clear_screen = "\27[2J"
local cursor_home = "\27[H"
local cursor_hide = "\27[?25l"
local cursor_show = "\27[?25h"
local reset_color = "\27[0m"

local color_codes = {
    [1] = "\27[1;36m", -- I: Cyan
    [2] = "\27[1;37m", -- O: White
    [3] = "\27[1;35m", -- T: Purple
    [4] = "\27[1;32m", -- S: Green
    [5] = "\27[1;31m", -- Z: Red
    [6] = "\27[1;34m", -- J: Blue
    [7] = "\27[1;33m"  -- L: Yellow
}

local function init_board()
    local board = {}
    for y = 1, board_height do
        board[y] = {}
        for x = 1, board_width do
            board[y][x] = 0 -- 0 for empty, piece ID for placed blocks
        end
    end
    return board
end

local function can_place_piece(board, piece, px, py)
    for y = 1, #piece do
        for x = 1, #piece[1] do
            if piece[y][x] == 1 then
                local board_x = px + x - 1
                local board_y = py + y - 1
                if board_x < 1 or board_x > board_width or board_y > board_height or
                   (board_y >= 1 and board[board_y][board_x] ~= 0) then
                    return false
                end
            end
        end
    end
    return true
end

local function place_piece(board, piece, piece_id, px, py)
    for y = 1, #piece do
        for x = 1, #piece[1] do
            if piece[y][x] == 1 then
                local board_x = px + x - 1
                local board_y = py + y - 1
                if board_y >= 1 and board_y <= board_height then
                    board[board_y][board_x] = piece_id -- Store piece ID for color
                end
            end
        end
    end
end

local function clear_lines(board)
    local lines_cleared = 0
    local y = board_height
    while y >= 1 do
        local full = true
        for x = 1, board_width do
            if board[y][x] == 0 then
                full = false
                break
            end
        end
        if full then
            table.remove(board, y)
            table.insert(board, 1, {})
            for x = 1, board_width do
                board[1][x] = 0
            end
            lines_cleared = lines_cleared + 1
        else
            y = y - 1
        end
    end
    return lines_cleared
end

local function rotate_piece(piece, piece_id, px, py, board)
    local new_piece = {}
    for x = 1, #piece[1] do
        new_piece[x] = {}
        for y = 1, #piece do
            new_piece[x][#piece + 1 - y] = piece[y][x]
        end
    end
    if can_place_piece(board, new_piece, px, py) then
        return new_piece
    end
    return piece
end

function render(applet, board, piece, piece_id, px, py, score)
    local output = cursor_home
    output = output .. game_name .. " - Lines: " .. score .. "\r\n"
    output = output .. "+" .. string.rep("-", board_width * 2) .. "+\r\n"
    for y = 1, board_height do
        output = output .. "|"
        for x = 1, board_width do
            local char = "  "
            -- Current piece
            for py_idx = 1, #piece do
                for px_idx = 1, #piece[1] do
                    if piece[py_idx][px_idx] == 1 then
                        local board_x = px + px_idx - 1
                        local board_y = py + py_idx - 1
                        if board_x == x and board_y == y then
                            char = color_codes[piece_id] .. "[]" .. reset_color
                        end
                    end
                end
            end
            -- Placed blocks
            if board[y][x] ~= 0 then
                char = color_codes[board[y][x]] .. "[]" .. reset_color
            end
            output = output .. char
        end
        output = output .. "|\r\n"
    end
    output = output .. "+" .. string.rep("-", board_width * 2) .. "+\r\n"
    output = output .. "Use arrow keys to move, Up to rotate, q to quit"
    applet:send(output)
end

function handler(applet)
    local board = init_board()
    local piece_idx = math.random(#pieces)
    local current_piece = pieces[piece_idx].shape
    local piece_id = pieces[piece_idx].id
    local piece_x = math.floor(board_width / 2) - math.floor(#current_piece[1] / 2)
    local piece_y = 1
    local score = 0
    local game_over = false
    local delay = 500

    if not can_place_piece(board, current_piece, piece_x, piece_y) then
        game_over = true
    end

    applet:send(cursor_hide)
    applet:send(clear_screen)

    -- fall the piece by one line every delay
    local function fall_piece()
      while not game_over do
        piece_y = piece_y + 1
        if not can_place_piece(board, current_piece, piece_x, piece_y) then
            piece_y = piece_y - 1
            place_piece(board, current_piece, piece_id, piece_x, piece_y)
            score = score + clear_lines(board)
            piece_idx = math.random(#pieces)
            current_piece = pieces[piece_idx].shape
            piece_id = pieces[piece_idx].id
            piece_x = math.floor(board_width / 2) - math.floor(#current_piece[1] / 2)
            piece_y = 1
            if not can_place_piece(board, current_piece, piece_x, piece_y) then
                game_over = true
            end
        end
        core.msleep(delay)
      end
    end

    core.register_task(fall_piece)

    local function drop_piece()
        while can_place_piece(board, current_piece, piece_x, piece_y) do
            piece_y = piece_y + 1
        end
        piece_y = piece_y - 1
        place_piece(board, current_piece, piece_id, piece_x, piece_y)
        score = score + clear_lines(board)
        piece_idx = math.random(#pieces)
        current_piece = pieces[piece_idx].shape
        piece_id = pieces[piece_idx].id
        piece_x = math.floor(board_width / 2) - math.floor(#current_piece[1] / 2)
        piece_y = 1
        if not can_place_piece(board, current_piece, piece_x, piece_y) then
            game_over = true
        end
        render(applet, board, current_piece, piece_id, piece_x, piece_y, score)
    end

    while not game_over do
        render(applet, board, current_piece, piece_id, piece_x, piece_y, score)

        -- update the delay based on the score: 500 for 0 lines to 100ms for 100 lines.
        if score >= 100 then
          delay = 100
        else
          delay = 500 - 4*score
        end

        local input = applet:receive(1, delay)
        if input then
            if input == "" or input == "q" then
                game_over = true
            elseif input == "\27" then
                local a = applet:receive(1, delay)
                if a == "[" then
                    local b = applet:receive(1, delay)
                    if b == "A" then -- Up arrow (rotate clockwise)
                        current_piece = rotate_piece(current_piece, piece_id, piece_x, piece_y, board)
                    elseif b == "B" then -- Down arrow (full drop)
                        drop_piece()
                    elseif b == "C" then -- Right arrow
                        piece_x = piece_x + 1
                        if not can_place_piece(board, current_piece, piece_x, piece_y) then
                            piece_x = piece_x - 1
                        end
                    elseif b == "D" then -- Left arrow
                        piece_x = piece_x - 1
                        if not can_place_piece(board, current_piece, piece_x, piece_y) then
                            piece_x = piece_x + 1
                        end
                    end
                end
            end
        end
    end

    applet:send(clear_screen .. cursor_home .. "Game Over! Lines: " .. score .. "\r\n" .. cursor_show)
end

-- works as a TCP applet
core.register_service("trisdemo", "tcp", handler)

-- may also work on the CLI but requires an unbuffered handler
core.register_cli({"trisdemo"}, "Play a simple falling pieces game", handler)
