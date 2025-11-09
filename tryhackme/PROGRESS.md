# CTF Challenges & Boxes (10)

| Room | Difficulty | Key Topics |
|------|-----------|------------|
| Blue | Easy | EternalBlue, Windows exploitation, Metasploit |
| Pickle Rick | Easy | Web exploitation, command injection, Linux PrivEsc |
| RootMe | Easy | Web enumeration, file upload, SUID exploitation |
| Basic Pentesting | Easy | SMB, SSH, web exploitation, privilege escalation |
| Kenobi | Easy | Samba, ProFTPD, path variable manipulation |
| Steel Mountain | Easy | Windows box, RCE, PowerShell PrivEsc |
| Alfred | Easy | Jenkins exploitation, Windows tokens |
| Ice | Easy | Windows exploitation, privilege escalation |
| Ignite | Easy | CMS exploitation, configuration vulnerabilities |
| **Internal** | **Hard** | **WordPress, SSH tunneling, Jenkins, Docker, multi-stage privesc** |

---

## 📝 Latest Addition: Internal Box

**Completed:** November 9, 2025  
**Difficulty:** Hard ⭐⭐⭐  
**Time:** 4.5 hours  

### Key Techniques:
1. WordPress theme editor exploitation (RCE)
2. Manual credential hunting (`find / -name "*wp*"`)
3. SSH local port forwarding to internal Jenkins
4. Hydra web form brute force
5. Jenkins Script Console exploitation (Groovy)
6. Docker container enumeration
7. Multi-layered privilege escalation (6 stages)

### Attack Chain:
```
Nmap → Gobuster → WordPress → WPScan
  ↓
Theme Editor RCE → www-data shell
  ↓
/opt/wp-save.txt → aubreanna user
  ↓
jenkins.txt → SSH Tunnel → Internal Jenkins
  ↓
Hydra → admin:spongebob
  ↓
Script Console → jenkins container
  ↓
/opt/note.txt → root credentials → ROOT
```

### Lessons Learned:
- LinPEAS doesn't catch everything - manual enumeration is critical
- Pattern-based file searching reveals hidden credentials
- SSH tunneling is essential for accessing internal services
- Docker containers can expose sensitive information
- Multi-layered defenses can all fail if each has weaknesses

**Full Writeup:** [internal.md](./writeups/boxes/internal.md)
