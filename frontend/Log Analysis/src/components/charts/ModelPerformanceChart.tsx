import React, { useRef } from "react";
import type * as echarts from "echarts";
import useChart from "../../hooks/useChart";
import { BORD, T, ACC, TT } from "../../constants/theme";

interface Props {
  ready: boolean;
}

const modelOpt: echarts.EChartsOption = {
  backgroundColor:"transparent",
  tooltip:{ trigger:"axis", ...TT },
  grid:{ top:10, right:14, bottom:28, left:8, containLabel:true },
  xAxis:{ type:"category", data:["Ep1","Ep2","Ep3","Ep4","Ep5","Ep6","Ep7","Ep8"], axisLabel:{ color:T.lo, fontSize:10, fontFamily:"JetBrains Mono" }, axisLine:{ lineStyle:{ color:BORD.dim } }, axisTick:{ show:false } },
  yAxis:{ type:"value", min:80, max:100, axisLabel:{ color:T.lo, fontSize:10, fontFamily:"JetBrains Mono", formatter:"{value}%" }, splitLine:{ lineStyle:{ color:BORD.dim } } },
  series:[
    { name:"Accuracy", type:"bar",  data:[84,87,90,92,94,95,96,96.4], barMaxWidth:28,
      itemStyle:{ borderRadius:[4,4,0,0], color:{ type:"linear",x:0,y:0,x2:0,y2:1, colorStops:[{offset:0,color:ACC.cyan},{offset:1,color:"rgba(0,217,255,.28)"}] } } },
    { name:"F1 Score", type:"line", data:[82,85,88,91,93,94,95.2,95.8],
      lineStyle:{ color:ACC.purple, width:2.5 }, itemStyle:{ color:ACC.purple }, symbolSize:6, symbol:"circle" },
  ],
};

const ModelPerformanceChart: React.FC<Props> = ({ ready }) => {
  const ref = useRef<HTMLDivElement>(null);
  useChart(ref, modelOpt, ready);
  return <div ref={ref} style={{ width:"100%", height:190 }} />;
};

export default ModelPerformanceChart;
