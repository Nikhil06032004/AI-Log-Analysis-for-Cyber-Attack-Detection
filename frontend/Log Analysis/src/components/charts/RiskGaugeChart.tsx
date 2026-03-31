import React, { useRef } from "react";
import type * as echarts from "echarts";
import useChart from "../../hooks/useChart";
import { T, ACC } from "../../constants/theme";

interface Props {
  ready: boolean;
}

const gaugeOpt: echarts.EChartsOption = {
  backgroundColor:"transparent",
  series:[{
    type:"gauge", radius:"90%", startAngle:210, endAngle:-30, min:0, max:100, splitNumber:5,
    pointer:{ length:"56%", width:5, itemStyle:{ color:ACC.red } },
    axisLine:{ lineStyle:{ width:16, color:[[.25,ACC.green],[.5,ACC.yellow],[.75,ACC.orange],[1,ACC.red]] } },
    axisTick:{ show:false }, splitLine:{ show:false },
    axisLabel:{ color:T.md, fontSize:10, fontFamily:"JetBrains Mono", distance:-22 },
    detail:{ valueAnimation:true, formatter:"{value}", color:ACC.red, fontSize:30, fontWeight:"bold", offsetCenter:[0,"38%"], fontFamily:"JetBrains Mono" },
    title:{ color:T.lo, fontSize:11, offsetCenter:[0,"60%"], fontFamily:"JetBrains Mono" },
    data:[{ value:73, name:"Risk Score" }],
  }],
};

const RiskGaugeChart: React.FC<Props> = ({ ready }) => {
  const ref = useRef<HTMLDivElement>(null);
  useChart(ref, gaugeOpt, ready);
  return <div ref={ref} style={{ width:"100%", height:196 }} />;
};

export default RiskGaugeChart;
