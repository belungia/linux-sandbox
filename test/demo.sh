#!/usr/bin/env bash
# Демонстрация базовой функциональности песочницы (запускать в ВМ под root).
# Предполагается, что модуль уже собран. Скрипт сам грузит и выгружает sandbox.ko.
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
KO="$HERE/sandbox.ko"
RUN="$HERE/tools/sandbox_run"
PASS=0; FAIL=0

ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

[ "$(id -u)" = "0" ] || { echo "нужен root"; exit 1; }
[ -f "$KO" ]  || { echo "нет $KO - соберите: make"; exit 1; }
[ -x "$RUN" ] || { echo "нет $RUN - соберите: make tools"; exit 1; }

echo "== загрузка модуля =="
rmmod sandbox 2>/dev/null
insmod "$KO" || { echo "insmod не удался"; dmesg | tail; exit 1; }
[ -e /proc/sandbox/control ] && ok "интерфейс /proc/sandbox создан" || bad "нет /proc/sandbox"

echo "== req3/4: запись нового файла не видна снаружи =="
PROBE=/tmp/sb_probe.$$
rm -f "$PROBE"
INSIDE="$("$RUN" bash -c "echo SANDBOXED > $PROBE; cat $PROBE; stat -c %s $PROBE")"
echo "    внутри: $INSIDE"
echo "$INSIDE" | grep -q SANDBOXED && ok "процесс видит свою запись" || bad "запись не видна процессу"
[ ! -e "$PROBE" ] && ok "снаружи файла нет (реальная ФС чиста)" || bad "файл протёк в реальную ФС: $PROBE"

echo "== req3/4: модификация существующего файла =="
ORIG=/tmp/sb_orig.$$
echo -n AAA > "$ORIG"
INSIDE="$("$RUN" bash -c "echo -n BBB >> $ORIG; cat $ORIG")"
echo "    внутри cat: $INSIDE"
[ "$INSIDE" = "AAABBB" ] && ok "процесс видит изменённое содержимое" || bad "ожидали AAABBB, получили $INSIDE"
[ "$(cat "$ORIG")" = "AAA" ] && ok "снаружи оригинал не изменён (AAA)" || bad "оригинал испорчен: $(cat "$ORIG")"

echo "== req3: удаление видно только в песочнице =="
INSIDE="$("$RUN" bash -c "rm $ORIG; cat $ORIG 2>&1; echo rc=\$?")"
echo "    внутри: $INSIDE"
echo "$INSIDE" | grep -qiE "No such file|rc=[^0]" && ok "в песочнице файл удалён" || bad "удаление не сэмулировано"
[ -e "$ORIG" ] && ok "снаружи файл цел" || bad "файл реально удалён"

echo "== req5: два независимых процесса видят своё =="
SHARED=/tmp/sb_shared.$$
echo -n ORIG > "$SHARED"
A="$("$RUN" bash -c "echo -n AAA > $SHARED; cat $SHARED")"
B="$("$RUN" bash -c "echo -n BBB > $SHARED; cat $SHARED")"
echo "    proc A: $A   proc B: $B   реал: $(cat "$SHARED")"
{ [ "$A" = AAA ] && [ "$B" = BBB ]; } && ok "каждый видит свою версию" || bad "изоляция нарушена"
[ "$(cat "$SHARED")" = ORIG ] && ok "реальный файл не тронут (ORIG)" || bad "реальный файл изменён"

echo "== status =="
cat /proc/sandbox/status

echo "== выгрузка =="
rmmod sandbox && ok "модуль выгружен" || bad "rmmod не удался"
rm -f "$ORIG" "$SHARED" "$PROBE" 2>/dev/null

echo
echo "ИТОГ: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = 0 ] || exit 1
