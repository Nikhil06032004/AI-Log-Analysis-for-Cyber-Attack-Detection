import React, { useRef } from "react";
import type * as echarts from "echarts";
import useChart from "../../hooks/useChart";
import { T, ACC, TT } from "../../constants/theme";

interface Props {
  ready: boolean;
}

const geoOpt: echarts.EChartsOption = {
  backgroundColor:"transparent",
  tooltip:{ trigger:"item", ...TT },
  legend:{ orient:"vertical", right:8, top:"middle", textStyle:{ color:T.md, fontSize:10, fontFamily:"JetBrains Mono" }, icon:"circle", itemWidth:8, itemHeight:8, itemGap:8 },
  series:[{
    type:"pie", radius:["28%","60%"], center:["38%","50%"], roseType:"radius",
    data:[
      { value:38, name:"Russia",  itemStyle:{ color:ACC.red    } },
      { value:27, name:"China",   itemStyle:{ color:ACC.orange  } },
      { value:18, name:"USA",     itemStyle:{ color:ACC.yellow  } },
      { value:10, name:"Germany", itemStyle:{ color:ACC.purple  } },
      { value:7,  name:"Other",   itemStyle:{ color:T.lo        } },
    ],
    label:{ show:false },
  }],
};

const AttackOriginChart: React.FC<Props> = ({ ready }) => {
  const ref = useRef<HTMLDivElement>(null);
  useChart(ref, geoOpt, ready);
  return <div ref={ref} style={{ width:"100%", height:220 }} />;
};

export default AttackOriginChart;
