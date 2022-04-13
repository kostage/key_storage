package password_storage

import (
	"fmt"
	"sort"
	"strings"
)

type byName []*PasswordRecord

func (s byName) Len() int {
	return len(s)
}
func (s byName) Swap(i, j int) {
	s[i].Name, s[j].Name = s[j].Name, s[i].Name
}

func (s byName) Less(i, j int) bool {
	if cmp := strings.Compare(s[i].Name, s[j].Name); cmp < 0 {
		return true
	}
	return false
}

func findSorted(records []*PasswordRecord, name string) (*PasswordRecord, error) {
	for _, rec := range records {
		if rec.Name == name {
			return rec, nil
		}
	}
	return nil, fmt.Errorf("password not found")
}

func insertSorted(records []*PasswordRecord, new *PasswordRecord) ([]*PasswordRecord, error) {
	record, _ := findSorted(records, new.Name)
	if record != nil {
		return records, fmt.Errorf("password already exists")
	}
	records = append(records, new)
	sort.Sort(byName(records))
	return records, nil
}

func deleteSorted(records []*PasswordRecord, name string) ([]*PasswordRecord, error) {
	found := false
	num := 0
	for i := range records {
		if records[i].Name == name {
			found = true
			num = i
			break
		}
	}
	if found {
		records = append(records[:num], records[num+1:]...)
		return records, nil
	} else {
		return records, fmt.Errorf("password not found")
	}
}
