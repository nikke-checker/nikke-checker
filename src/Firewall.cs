using System;
using System.Collections;
using System.Linq;
using System.Reflection;
using static NikkeChecker.I18n;

namespace NikkeChecker
{
    /// <summary>
    /// Windows 방화벽 규칙 (HNetCfg.FwPolicy2 COM). 이름만 보지 않고 내용(사용, 아웃바운드, 차단, 두 IP)까지 확인한다.
    /// 읽기는 일반 권한으로 되고, 추가·삭제는 관리자 권한이 필요하다.
    /// </summary>
    public static class Firewall
    {
        private const int DirectionOut = 2, ActionBlock = 0, ProfilesAll = 0x7FFFFFFF;

        private static object Policy() => Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true));
        private static object Get(object o, string name) => o.GetType().InvokeMember(name, BindingFlags.GetProperty, null, o, null);
        private static void Set(object o, string name, object v) => o.GetType().InvokeMember(name, BindingFlags.SetProperty, null, o, new[] { v });
        private static void Call(object o, string name, params object[] args) => o.GetType().InvokeMember(name, BindingFlags.InvokeMethod, null, o, args);

        private static object FindRule(object rules, string name)
        {
            foreach (var r in (IEnumerable)rules)
                if (string.Equals(Get(r, "Name") as string, name, StringComparison.OrdinalIgnoreCase)) return r;
            return null;
        }

        private static bool IsValid(object r)
        {
            if (r == null) return false;
            if (!(Get(r, "Enabled") is bool en) || !en) return false;
            if (Convert.ToInt32(Get(r, "Direction")) != DirectionOut) return false;
            if (Convert.ToInt32(Get(r, "Action")) != ActionBlock) return false;
            var addrs = ((Get(r, "RemoteAddresses") as string) ?? "")
                .Split(',').Select(a => a.Split('/')[0].Trim()).ToList();
            return Iocs.C2Ips.All(ip => addrs.Contains(ip));
        }

        /// <summary>두 IP 를 막는 유효한 규칙이 있는지.</summary>
        public static bool RuleIsValid()
        {
            try { return IsValid(FindRule(Get(Policy(), "Rules"), Iocs.FirewallRuleName)); }
            catch { return false; }
        }

        /// <summary>규칙이 없거나 내용이 다르면 다시 만든다 (관리자 권한). 실패한 작업 수를 돌려준다.</summary>
        public static int Ensure(Logger log)
        {
            var ips = string.Join(", ", Iocs.C2Ips);
            try
            {
                var rules = Get(Policy(), "Rules");
                var existing = FindRule(rules, Iocs.FirewallRuleName);
                if (IsValid(existing)) { log(L($"[-] 방화벽: 차단 규칙이 이미 있습니다 ({ips})", $"[-] Firewall: the block rule already exists ({ips})"), LogLevel.Detail); return 0; }
                if (existing != null) Call(rules, "Remove", Iocs.FirewallRuleName);

                var rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true));
                Set(rule, "Name", Iocs.FirewallRuleName);
                Set(rule, "Description", "Blocks the NIKKE PC launcher malware (insightjs) servers - NikkeChecker");
                Set(rule, "Direction", DirectionOut);
                Set(rule, "Action", ActionBlock);
                Set(rule, "RemoteAddresses", string.Join(",", Iocs.C2Ips));
                Set(rule, "Profiles", ProfilesAll);
                Set(rule, "Enabled", true);
                Call(rules, "Add", rule);

                if (IsValid(FindRule(Get(Policy(), "Rules"), Iocs.FirewallRuleName)))
                {
                    log(L($"[+] 방화벽 아웃바운드 차단 등록·확인: {ips}", $"[+] Firewall outbound block added and verified: {ips}"), LogLevel.Action);
                    return 0;
                }
                log(L("[X] 방화벽 규칙을 만들었지만 확인에 실패했습니다", "[X] Created the firewall rule but could not verify it"), LogLevel.Bad);
                return 1;
            }
            catch (Exception ex)
            {
                log(L("[X] 방화벽 규칙 등록 실패: ", "[X] Could not add the firewall rule: ") + (ex is TargetInvocationException t && t.InnerException != null ? t.InnerException.Message : ex.Message), LogLevel.Bad);
                return 1;
            }
        }
    }
}
