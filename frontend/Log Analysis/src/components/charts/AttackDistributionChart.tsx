import React, { useRef } from "react";
import type * as echarts from "echarts";
import useChart from "../../hooks/useChart";
import { T, ACC, TT } from "../../constants/theme";

interface Props {
  ready: boolean;
}

const donutOpt: echarts.EChartsOption = {
  backgroundColor:"transparent",
  tooltip:{ trigger:"item", ...TT },
  legend:{ orient:"vertical", right:8, top:"middle", textStyle:{ color:T.md, fontSize:10, fontFamily:"JetBrains Mono" }, icon:"circle", itemWidth:8, itemHeight:8, itemGap:8 },
  series:[{
    type:"pie", radius:["44%","70%"], center:["38%","50%"],
    data:[
      { value:35, name:"Brute Force",  itemStyle:{ color:ACC.red    } },
      { value:22, name:"Port Scan",    itemStyle:{ color:ACC.orange  } },
      { value:18, name:"SQL Inject",   itemStyle:{ color:ACC.yellow  } },
      { value:12, name:"Phishing",     itemStyle:{ color:ACC.purple  } },
      { value:8,  name:"Malware",      itemStyle:{ color:ACC.cyan    } },
      { value:5,  name:"Exfiltration", itemStyle:{ color:ACC.green   } },
    ],
    label:{ show:false },
    emphasis:{ scale:true, scaleSize:6 },
  }],
};

const AttackDistributionChart: React.FC<Props> = ({ ready }) => {
  const ref = useRef<HTMLDivElement>(null);
  useChart(ref, donutOpt, ready);
  return <div ref={ref} style={{ width:"100%", height:220 }} />;
};

export default AttackDistributionChart;
