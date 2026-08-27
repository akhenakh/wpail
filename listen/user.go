package listen

import (
	"os/user"
	"strconv"
	"sync"
)

var (
	userMu    sync.Mutex
	userCache = map[uint32]string{}
)

// UserName resolves uid to a login name via NSS and caches the result.
// Unknown uids fall back to their numeric form.
func UserName(uid uint32) string {
	userMu.Lock()
	defer userMu.Unlock()
	if n, ok := userCache[uid]; ok {
		return n
	}
	name := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(name); err == nil && u.Username != "" {
		name = u.Username
	}
	userCache[uid] = name
	return name
}
