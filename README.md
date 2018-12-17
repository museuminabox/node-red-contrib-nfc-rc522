# node-red-contrib-nfc-rc522

NFC reader node for Node RED.  Requires an SPI-connected RC522 RFID/NFC reader.  Must be run as root (for access to the spi bus in /dev/mem)

## Nodes

* **rpi rc522 rfid** Generates events when a tag is presented or removed.
* **rpi rc522 rfid read ndef** Read and decode any NDEF records in a Mifare or NTAG2xx tag
* **rpi rc522 rfid write ndef** Write NDEF records to a Mifare or NTAG2xx tag

