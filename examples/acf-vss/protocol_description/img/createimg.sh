# needs pip install nwdiag, but downgrade Pillow to 0.9.5
rm ./*.svg
packetdiag -T svg  acf_vss.diag
packetdiag -T svg  static_id.diag
packetdiag -T svg  interop_path.diag
packetdiag -T svg  string.diag
packetdiag -T svg  array.diag



