package session

import (
	"container/list"
	"net/http"
	"sync"
	"time"
)

var mempder = &MemProvider{list: list.New(), sessions: make(map[string]*list.Element)}

// memory session store.
// it saved sessions in a map in memory.
type MemSessionStore struct {
	sid          string                      //session id
	timeAccessed time.Time                   //last access time
	value        map[interface{}]interface{} //session store
	lock         sync.RWMutex
}

// set value to memory session
func (st *MemSessionStore) Set(key, value interface{}) error {
	st.lock.Lock()
	defer st.lock.Unlock()
	st.value[key] = value
	return nil
}

// get value from memory session by key
func (st *MemSessionStore) Get(key interface{}) interface{} {
	st.lock.RLock()
	defer st.lock.RUnlock()
	if v, ok := st.value[key]; ok {
		return v
	} else {
		return nil
	}
	return nil
}

// delete in memory session by key
func (st *MemSessionStore) Delete(key interface{}) error {
	st.lock.Lock()
	defer st.lock.Unlock()
	delete(st.value, key)
	return nil
}

// clear all values in memory session
func (st *MemSessionStore) Flush() error {
	st.lock.Lock()
	defer st.lock.Unlock()
	st.value = make(map[interface{}]interface{})
	return nil
}

// get this id of memory session store
func (st *MemSessionStore) SessionID() string {
	return st.sid
}

// Implement method, no used.
func (st *MemSessionStore) SessionRelease(w http.ResponseWriter) {
}

type MemProvider struct {
	lock        sync.RWMutex             // locker
	sessions    map[string]*list.Element // map in memory
	list        *list.List               // for gc
	maxlifetime int64
	config      string
}

// init memory session
func (pder *MemProvider) SessionInit(maxlifetime int64, config string) error {
	pder.maxlifetime = maxlifetime
	pder.config = config
	return nil
}

// get memory session store by sid
func (pder *MemProvider) SessionRead(sid string) (SessionStore, error) {
	pder.lock.RLock()
	if element, ok := pder.sessions[sid]; ok {
		go pder.SessionUpdate(sid)
		pder.lock.RUnlock()
		return element.Value.(*MemSessionStore), nil
	} else {
		pder.lock.RUnlock()
		pder.lock.Lock()
		newsess := &MemSessionStore{sid: sid, timeAccessed: time.Now(), value: make(map[interface{}]interface{})}
		element := pder.list.PushBack(newsess)
		pder.sessions[sid] = element
		pder.lock.Unlock()
		return newsess, nil
	}
	return nil, nil
}

// check session store exist in memory session by sid
func (pder *MemProvider) SessionExist(sid string) bool {
	pder.lock.RLock()
	defer pder.lock.RUnlock()
	if _, ok := pder.sessions[sid]; ok {
		return true
	} else {
		return false
	}
}

// generate new sid for session store in memory session
func (pder *MemProvider) SessionRegenerate(oldsid, sid string) (SessionStore, error) {
	pder.lock.RLock()
	if element, ok := pder.sessions[oldsid]; ok {
		go pder.SessionUpdate(oldsid)
		pder.lock.RUnlock()
		pder.lock.Lock()
		element.Value.(*MemSessionStore).sid = sid
		pder.sessions[sid] = element
		delete(pder.sessions, oldsid)
		pder.lock.Unlock()
		return element.Value.(*MemSessionStore), nil
	} else {
		pder.lock.RUnlock()
		pder.lock.Lock()
		newsess := &MemSessionStore{sid: sid, timeAccessed: time.Now(), value: make(map[interface{}]interface{})}
		element := pder.list.PushBack(newsess)
		pder.sessions[sid] = element
		pder.lock.Unlock()
		return newsess, nil
	}
	return nil, nil
}

// delete session store in memory session by id
func (pder *MemProvider) SessionDestroy(sid string) error {
	pder.lock.Lock()
	defer pder.lock.Unlock()
	if element, ok := pder.sessions[sid]; ok {
		delete(pder.sessions, sid)
		pder.list.Remove(element)
		return nil
	}
	return nil
}

// clean expired session stores in memory session
func (pder *MemProvider) SessionGC() {
	pder.lock.RLock()
	for {
		element := pder.list.Back()
		if element == nil {
			break
		}
		if (element.Value.(*MemSessionStore).timeAccessed.Unix() + pder.maxlifetime) < time.Now().Unix() {
			pder.lock.RUnlock()
			pder.lock.Lock()
			pder.list.Remove(element)
			delete(pder.sessions, element.Value.(*MemSessionStore).sid)
			pder.lock.Unlock()
			pder.lock.RLock()
		} else {
			break
		}
	}
	pder.lock.RUnlock()
}

// get count number of memory session
func (pder *MemProvider) SessionAll() int {
	return pder.list.Len()
}

// expand time of session store by id in memory session
func (pder *MemProvider) SessionUpdate(sid string) error {
	pder.lock.Lock()
	defer pder.lock.Unlock()
	if element, ok := pder.sessions[sid]; ok {
		element.Value.(*MemSessionStore).timeAccessed = time.Now()
		pder.list.MoveToFront(element)
		return nil
	}
	return nil
}

func init() {
	Register("memory", mempder)
}
