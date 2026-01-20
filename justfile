# print just recipes
default:
    just -l

# install Wireshark dissector
install-wireshark:
    ln -sf $(pwd)/wireshark-dissector/csp-zmq.lua $HOME/.local/lib/wireshark/plugins/csp-zmq.lua
