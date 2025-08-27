set datafile separator ","

set xtics 6 nomirror font ",17" 
set ytics 10 nomirror font ",17"

set xrange [6:24] 
set yrange [0.2:*]
set grid back lt 1 dt 3 lc rgb 'grey'
set border lt 1 dt 1 lc rgb 'black'

unset mxtics
unset mytics
set key left top
set key samplen 1 
set format x "2^{%0.f}" 

set logscale y 10      # This is for your y-axis (already correct)
set format y "10^{%L}" # This is for your y-axis (already correct)
set key font ",16"
set terminal pdfcairo enhanced color font "Helvetica ,15" size 3,3 background rgb 'white'
set xlabel "Registration batch size" offset 0,0,0 font ",17"
set ylabel "Server registration time (s)" offset 0,0,0 font ",17" 
set output 'reg_time_vs_batch_size.pdf' 


plot 'server_reg_update.csv' using 2:($1==26 ? $4 : 1/0) with lines lc rgb "#FF0000" linewidth 4 title "|D|= 2^{24}", \
     '' using 2:($1==32 ? $4 : 1/0) with lines lc rgb "#0000FF" linewidth 4 title "|D|= 2^{30}", \
     (2**x)/1000 with lines lc rgb "#000000" dashtype 2 notitle


set key font ",16"

set xlabel "Key update batch size" offset 0,0,0 font ",17"
set ylabel "Server key update time (s)" offset 0,0,0 font ",17" 
set output 'key_update_time.pdf' 
set ytics 10 nomirror font ",17"
set xrange [1:22] 
set yrange [*:*]

plot \
    'server_key_update.csv' using 2:($1==26 ? $4 : 1/0) with lines lc rgb "#FF0000" linewidth 4  title "|D|= 2^{24}", \
    'server_key_update.csv' using 2:($1==32 ? $4 : 1/0) with lines lc rgb "#0000FF" linewidth 4  title "|D|= 2^{30}", \


set xlabel "Dictionary size" offset 0,0,0 font ",17"
set ylabel "Server lookup time (ms)" offset 0,0,0 font ",17" 
set output 'server_lookup_time.pdf' 
set ytics 10 nomirror font ",17"
set xrange [20:32] 
set yrange [*:*]
set ytics 3 nomirror font ",17"
unset format y
set key font ",16"
plot \
    'server_lookup.csv' using 1:2 with lines lc rgb "#000000" linewidth 4 notitle, \
    'server_lookup.csv' using ($1==26 ? $1 : 1/0):2 with points pt 7 ps 1 lc rgb "blue" title "|D|= 2^{24}", \
    'server_lookup.csv' using ($1==32 ? $1 : 1/0):2 with points pt 7 ps 1 lc rgb "red"  title '|D|= 2^{30}'


set output 'client_time.pdf'
set format y "10^{%L}" # This is for your y-axis (already correct)

set xlabel "Dictionary size"
set ylabel "Verifier Lookup Time (ms)"

set format y "%g"
set xrange [18:30]
set yrange [*:*]
# set xtics 8 nomirror font ",17" 
set ytics 20 nomirror font ",17"
set key font ",16"
set key top left

plot \
'client.csv' using ($1-2):($2) with lines lc rgb "#000000" linewidth 4 notitle , \
    'client.csv' using ($1==26 ? $1-2 : 1/0):2 with points pt 7 ps 1 lc rgb "blue" title "|D|= 2^{24}", \
    'client.csv' using ($1==32 ? $1-2 : 1/0):2 with points pt 7 ps 1 lc rgb "red"  title '|D|= 2^{30}'

set output 'auditor_times.pdf'
set format y "10^{%L}" # This is for your y-axis (already correct)

set xlabel "Dictionary size"
set ylabel "Auditor verification Time (ms)"

set format y "%g"
set xrange [18:30]
set yrange [*:*]
# set xtics 8 nomirror font ",17" 
set ytics 20 nomirror font ",17"
set key font ",16"
set key top left

plot \
'client.csv' using ($1-2):($5) with lines lc rgb "#000000" linewidth 4 notitle  , \
    'client.csv' using ($1==26 ? $1-2 : 1/0):5 with points pt 7 ps 1 lc rgb "blue" title "|D|= 2^{24}", \
    'client.csv' using ($1==32 ? $1-2 : 1/0):5 with points pt 7 ps 1 lc rgb "red"  title '|D|= 2^{30}'

set output 'client_sizes.pdf'

set xlabel "Dictionary size"
set ylabel "Lookup proof size (KB)"

set format y "%g"
set xrange [18:30]
set yrange [*:*]
# set xtics 8 nomirror font ",17" 
set ytics 2 nomirror font ",17"
set key font ",16"
set key top left

plot \
'client.csv' using ($1-2):($3/1024) with lines lc rgb "#000000" linewidth 4 notitle  , \
    'client.csv' using ($1==26 ? $1-2 : 1/0):($3/1024) with points pt 7 ps 1 lc rgb "blue" title "|D|= 2^{24}", \
    'client.csv' using ($1==32 ? $1-2 : 1/0):($3/1024) with points pt 7 ps 1 lc rgb "red"  title '|D|= 2^{30}'


set output 'auditor_sizes.pdf'

set xlabel "Dictionary size"
set ylabel "Audit proof size (KB)"

set format y "%g"
set xrange [18:30]
set yrange [2:*]
# set xtics 8 nomirror font ",17" 
set ytics 2 nomirror font ",17"

set key top left

set key font ",16"

plot \
    'server_reg_update.csv' using ($1-2):($5/1024) with lines lc rgb "#000000" linewidth 4 notitle, \
    'server_reg_update.csv' using ((($1==26 && $2==4) ? $1-2 : 1/0)):($5/1024) with points pt 7 ps 1 lc rgb "blue" title "|D|= 2^{24}", \
    'server_reg_update.csv' using ((($1==32 && $2==4) ? $1-2 : 1/0)):($5/1024) with points pt 7 ps 1 lc rgb "red"  title "|D|= 2^{30}"