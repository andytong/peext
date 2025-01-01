#pragma once
#include <map>
#include <string>
#include <vector>

using namespace std;

template <typename T>
class cmdline
{
	using tstring = basic_string<T, char_traits<T>, allocator<T>>;
public:
	cmdline(const T* cmd) {
		parse_cmd(cmd);
	}
	~cmdline() {

	}
	bool IsHasSwitch(const T* cmd) {
		return map_cmd_.find(cmd) != map_cmd_.end();
	}
	bool IsHasSwitch() {
		return is_has_switch_;
	}

	vector<tstring>* GetSwitchCmd(const T* cmd) {
		auto it = map_cmd_.find(cmd);
		if (it != map_cmd_.end()) {
			return &it->second;
		}
		return nullptr;
	}
private:
	bool get_args(tstring& cmd, vector<tstring> &args){

		size_t off = 0;
		size_t off_leftquot = -1;
		size_t off_rightquot = -1;
		size_t length = cmd.size();
		bool is_has_quot = false;
		T space = static_cast<T>(' ');
		T quot = static_cast<T>('\"');

		if (cmd.empty())
			return true;
		size_t off_next = cmd.find(space);
		if (off_next == -1) {
			args.push_back(cmd);
			return true;
		}
		off_leftquot = cmd.find(quot);
		if (off_leftquot != -1) {
			off_rightquot = cmd.find(quot, off_leftquot + 1);
			if (off_rightquot != -1) {
				is_has_quot = true;
			}
		}
		while (off_next != -1 && off < length) {
			if (is_has_quot) {
				if (off_next > off_leftquot && off_next < off_rightquot) {
					off_next = cmd.find(quot, off_rightquot + 1);
					continue;
				} else {
					is_has_quot = false;
					off_leftquot = cmd.find(quot, off_next);
					if (off_leftquot == -1) {
						off_rightquot = cmd.find(quot, off_leftquot + 1);
						if (off_rightquot != -1) {
							is_has_quot = true;
						}
					}
				}
			}

			if (off_next > off) {
				tstring arg = cmd.substr(off, off_next - off);
				args.push_back(move(arg));
			}
			off = off_next + 1;
			off_next = cmd.find(space, off);
		}

		if (off_next == -1 && off < length)
		{
			tstring arg = cmd.substr(off);
			args.push_back(move(arg));
		}

		

		return true;
	}

	void parse_cmd(const T* cmd) {
		tstring p = cmd;
		T switch_char = static_cast<T>('-');
		bool is_switch = false;
		tstring swich_cmd;
		vector<tstring> args;
		get_args(p, args);
		for (auto item : args) {
			if (*item.begin() == switch_char) {
				swich_cmd = item;
				is_switch = true;
				is_has_switch_ = true;
				if (map_cmd_.find(swich_cmd) == map_cmd_.end()) {
					map_cmd_.insert(make_pair(swich_cmd, vector<tstring>()));
				}
				continue;
			}

			if (is_switch) {
				map_cmd_[swich_cmd].push_back(item);
			} else {
				map_cmd_[tstring()].push_back(item);
			}
		}
	}

private:
	map<tstring, vector<tstring>> map_cmd_;
	bool is_has_switch_ = false;
};

