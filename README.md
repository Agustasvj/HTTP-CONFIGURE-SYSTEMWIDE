# System-Wide HTTP Tunnel Configuration

A Python-based tool for configuring system-wide HTTP tunneling with support for both Windows and Linux/Unix systems.

## Features

- **System Proxy Toggle**: Enable/disable system-wide proxy settings
- **TUN Interface**: Network-level tunneling (Linux/Unix only)
- **Real-time Logging**: Monitor connection status and events
- **Automatic Cleanup**: Proper cleanup of system settings on exit

## Configuration

The application provides a GUI interface with:
- Connection status indicator
- System proxy toggle
- TUN interface toggle (Linux/Unix)
- Log viewer
- Connect/Disconnect buttons

## Technical Details

### Windows Implementation
- Uses Windows Registry for system proxy configuration
- Manages WinHTTP settings
- Handles service restarts automatically

### Linux/Unix Implementation
- Uses TUN interface for network-level tunneling
- Manages system proxy settings via gsettings/networksetup
- Handles routing table updates

## Troubleshooting

### Common Issues

1. **Windows Permission Error**
   - Run as Administrator
   - Check Windows Defender settings

2. **Linux Module Error**
   - Install python-dev package
   - Check kernel TUN module status

3. **Connection Issues**
   - Verify proxy settings
   - Check firewall rules
   - Ensure proper permissions

## Security Considerations

- Runs with elevated privileges
- Modifies system network settings
- Handle with care in production environments

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Python community
- Contributors and testers
- Open source projects used

## Support

For support, please open an issue in the GitHub repository.

## Disclaimer

Use at your own risk. Always backup your system settings before using system-wide network tools.

