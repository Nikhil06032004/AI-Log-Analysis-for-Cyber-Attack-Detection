import React, { useRef } from "react";
import type * as echarts from "echarts";
import useChart from "../../hooks/useChart";
import { BORD, T, ACC, TT } from "../../constants/theme";

interface Props {
  ready: boolean;
}

const barOpt: echarts.EChartsOption = {
  backgroundColor:"transparent",
  tooltip:{ trigger:"axis", ...TT },
  grid:{ top:10, right:14, bottom:28, left:8, containLabel:true },
  xAxis:{ type:"category", data:Array.from({length:12},(_,i)=>`${(8+i).toString().padStart(2,"0")}:00`), axisLabel:{ color:T.lo, fontSize:9, fontFamily:"JetBrains Mono", interval:2 }, axisLine:{ lineStyle:{ color:BORD.dim } }, axisTick:{ show:false } },
  yAxis:{ type:"value", axisLabel:{ color:T.lo, fontSize:9, fontFamily:"JetBrains Mono" }, splitLine:{ lineStyle:{ color:BORD.dim } } },
  series:[{ type:"bar", data:[450,820,1200,980,1450,1100,890,1350,920,1600,1400,1250], barMaxWidth:18,
    itemStyle:{ borderRadius:[4,4,0,0], color:{ type:"linear",x:0,y:0,x2:0,y2:1, colorStops:[{offset:0,color:ACC.cyan},{offset:1,color:"rgba(0,217,255,.18)"}] } } }],
};

const LogVolumeChart: React.FC<Props> = ({ ready }) => {
  const ref = useRef<HTMLDivElement>(null);
  useChart(ref, barOpt, ready);
  return <div ref={ref} style={{ width:"100%", height:220 }} />;
};

export default LogVolumeChart;
