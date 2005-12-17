main() {
  write(1, "HTTP", 4);
  write(1, "/1.0", 4);
  write(1, " 200", 4);
  write(1, " OK\r\n", 5);
  write(1, "TOTO: 1\r\n", 9);
  write(1, "Hdr2: 2\r\n", 9);
  write(1, "Hdr3:", 5);
  write(1, " 2\r\n", 4);
  write(1, "\r\n\r\n", 4);
  write(1, "DATA\r\n", 6);
}

