import React, { useRef } from "react";
import type * as echarts from "echarts";
import useChart from "../../hooks/useChart";
import { BORD, T, ACC, TT } from "../../constants/theme";

interface Props {
  ready: boolean;
}

const trendOpt: echarts.EChartsOption = {
  backgroundColor:"transparent",
  tooltip:{ trigger:"axis", ...TT },
  legend:{ data:["Critical","High","Medium","Low"], bottom:2, textStyle:{ color:T.md, fontSize:10, fontFamily:"JetBrains Mono" }, itemGap:18 },
  grid:{ top:12, right:16, bottom:42, left:8, containLabel:true },
  xAxis:{ type:"category", data:["08:00","09:00","10:00","11:00","12:00","13:00","14:00"], axisLine:{ lineStyle:{ color:BORD.dim } }, axisTick:{ show:false }, axisLabel:{ color:T.lo, fontSize:10, fontFamily:"JetBrains Mono" } },
  yAxis:{ type:"value", splitLine:{ lineStyle:{ color:BORD.dim } }, axisLabel:{ color:T.lo, fontSize:10, fontFamily:"JetBrains Mono" } },
  series:[
    { name:"Critical", type:"line", smooth:.4, data:[2,3,1,4,5,3,6],      lineStyle:{ color:ACC.red,    width:2.5 }, itemStyle:{ color:ACC.red    }, areaStyle:{ color:"rgba(255,69,105,.13)" }, symbolSize:6, symbol:"circle" },
    { name:"High",     type:"line", smooth:.4, data:[5,4,6,3,7,8,5],      lineStyle:{ color:ACC.orange, width:2.5 }, itemStyle:{ color:ACC.orange  }, areaStyle:{ color:"rgba(255,142,60,.09)" }, symbolSize:6, symbol:"circle" },
    { name:"Medium",   type:"line", smooth:.4, data:[8,10,7,12,9,11,8],   lineStyle:{ color:ACC.yellow, width:2.5 }, itemStyle:{ color:ACC.yellow  }, areaStyle:{ color:"rgba(255,210,63,.06)" }, symbolSize:6, symbol:"circle" },
    { name:"Low",      type:"line", smooth:.4, data:[15,12,18,14,16,13,17],lineStyle:{ color:ACC.green,  width:2.5 }, itemStyle:{ color:ACC.green   }, areaStyle:{ color:"rgba(0,230,118,.05)"  }, symbolSize:6, symbol:"circle" },
  ],
};

const ThreatTrendChart: React.FC<Props> = ({ ready }) => {
  const ref = useRef<HTMLDivElement>(null);
  useChart(ref, trendOpt, ready);
  return <div ref={ref} style={{ width:"100%", height:230 }} />;
};

export default ThreatTrendChart;
