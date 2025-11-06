# Production Deployment Checklist

## Pre-Deployment

- [ ] **Set DEBUG = False** in `src/main.py`
- [ ] **Change admin password** in `config.json` from default
- [ ] **Generate strong API keys** using the dashboard
- [ ] **Configure rate limits** appropriate for your use case
- [ ] **Test all endpoints** with sample requests
- [ ] **Verify image upload** works with test images
- [ ] **Check LMArena tokens** are valid (arena-auth-prod-v1, cf_clearance)

## Security

- [ ] **Use HTTPS** via reverse proxy (nginx, Caddy, Traefik)
- [ ] **Restrict dashboard access** (IP whitelist or VPN)
- [ ] **Set strong passwords** for all accounts
- [ ] **Regularly rotate API keys** for security
- [ ] **Monitor for unauthorized access** in logs
- [ ] **Backup config.json** regularly

## Infrastructure

- [ ] **Set up reverse proxy** with SSL certificates
- [ ] **Configure systemd service** (or equivalent) for auto-restart
- [ ] **Set up monitoring** (response times, error rates)
- [ ] **Configure log rotation** to prevent disk fill
- [ ] **Test failover/restart** behavior
- [ ] **Document deployment** process for your team

## Performance

- [ ] **Test concurrent requests** to verify performance
- [ ] **Monitor memory usage** under load
- [ ] **Check response times** for acceptable latency
- [ ] **Test streaming mode** if using long responses
- [ ] **Verify image upload** doesn't cause timeouts

## Monitoring

- [ ] **Set up health checks** (e.g., /api/v1/models endpoint)
- [ ] **Monitor error rates** from logs
- [ ] **Track model usage** via dashboard statistics
- [ ] **Set up alerts** for high error rates or downtime
- [ ] **Monitor disk space** for logs and config backups

## Testing

- [ ] **Test with OpenAI SDK** to verify compatibility
- [ ] **Test error handling** (invalid keys, missing fields, etc.)
- [ ] **Test rate limiting** to verify it works correctly
- [ ] **Test image uploads** with various formats and sizes
- [ ] **Test streaming responses** if using that feature
- [ ] **Test multi-turn conversations** to verify session management

## Documentation

- [ ] **Document API endpoint** URL for your users
- [ ] **Document available models** and capabilities
- [ ] **Document rate limits** and usage policies
- [ ] **Document image support** and size limits
- [ ] **Document error codes** and troubleshooting
- [ ] **Create usage examples** for common scenarios

## Post-Deployment

- [ ] **Monitor logs** for first 24 hours
- [ ] **Verify all features** work in production
- [ ] **Test from external network** to verify accessibility
- [ ] **Check dashboard** is accessible and functional
- [ ] **Verify stats tracking** is working correctly
- [ ] **Document any issues** and resolutions

## Maintenance

- [ ] **Schedule regular token rotation** (arena-auth-prod-v1, cf_clearance)
- [ ] **Review API key usage** monthly
- [ ] **Check for updates** to dependencies
- [ ] **Monitor LMArena** for API changes
- [ ] **Backup configuration** weekly
- [ ] **Review logs** for suspicious activity

## Emergency Procedures

- [ ] **Document restart procedure** for service
- [ ] **Document token refresh** process
- [ ] **Document rollback procedure** if needed
- [ ] **Create emergency contacts** list
- [ ] **Test backup restoration** procedure
- [ ] **Document common issues** and fixes

---

## Quick Start Commands

### Check Service Status
```bash
sudo systemctl status lmarenabridge
```

### View Recent Logs
```bash
sudo journalctl -u lmarenabridge -n 100 -f
```

### Restart Service
```bash
sudo systemctl restart lmarenabridge
```

### Test API Endpoint
```bash
curl http://localhost:8000/api/v1/models \
  -H "Authorization: Bearer sk-lmab-your-key-here"
```

### Check Disk Space
```bash
df -h
```

### Monitor Process
```bash
htop
```
