# imports
require 'socket'
require 'digest/sha1'

# Create server
server = TCPServer.new('localhost', 8080)
response_message = 'Hello, Client!'

loop do
  # Wait for a connection
  socket = server.accept
  warn 'Incoming Request!'

  http_request = ''
  while (line = socket.gets) && (line != "\r\n")
    http_request += line
  end

  # Handshake
  get_socket_key = /^Sec-WebSocket-Key: (\S+)/
  if match = http_request.match(get_socket_key)
    websocket_key = match[1]
    warn "Websockets handshake was detected with key: #{websocket_key}"
  else
    warn 'Aborting connection without websocket...'
    socket.close
    next
  end

  # generating valid answer
  response_key = Digest::SHA1.base64digest([websocket_key, '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'].join)
  warn "Responding to handshake with key: #{response_key}"

  socket.write <<~EOS
    HTTP/1.1 101 Switching Protocols
    Upgrade: websocket
    Connection: Upgrade
    Sec-WebSocket-Accept: #{response_key}

  EOS

  warn 'Handshake Completed!'

  # Receiving data

  # Byte 1: FIN and Opcode
  first_byte = socket.getbyte
  fin = first_byte & 0b10000000
  opcode = first_byte & 0b00001111

  raise "We don't support continuations" unless fin
  raise 'We only support opcode 1' unless opcode == 1

  # Byte 2: MASK and payload length
  second_byte = socket.getbyte
  is_masked = second_byte & 0b10000000
  payload_size = second_byte & 0b01111111

  raise 'All frames sent to a server should be masked according to the websocket spec' unless is_masked
  raise 'support payloads < 126 bytes in length' unless payload_size < 126

  warn "Payload size: #{payload_size} bytes"

  # Bytes 3-7: The masking key
  mask = 4.times.map do
    socket.getbyte
  end

  warn "Got mask: #{mask.inspect}"

  # Bytes 8 and up: The payload
  data = payload_size.times.map do
    socket.getbyte
  end
  warn "Got masked data: #{data.inspect}"

  unmasked_data = data.each_with_index.map do |byte, i|
    byte ^ mask[i % 4]
  end
  warn "Unmasked the data: #{unmasked_data.inspect}"
  warn "Converted to a string: #{unmasked_data.pack('C*').force_encoding('utf-8').inspect}"

  # Sending data back to the client
  warn "\n\n\n\nEnviando a mensagem: #{response_message.inspect}"
  output = [
    0b10000001,
    response_message.length,
    response_message
  ]

  socket.write output.pack("CCA#{response_message.size}")

  # Closing connection
  socket.close
end
