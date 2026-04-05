import React, { useRef, useEffect } from "react";
import * as echarts from "echarts";
import { T, ACC, TT } from "../../constants/theme";

export interface AttackDataItem {
  name: string;
  value: number;
  color: string;
}

interface Props {
  ready: boolean;
  data?: AttackDataItem[];
}

const DEFAULT_DATA: AttackDataItem[] = [
  { name: "Brute Force",  value: 35, color: ACC.red    },
  { name: "Port Scan",    value: 22, color: ACC.orange  },
  { name: "DOS Attack",   value: 18, color: ACC.yellow  },
  { name: "Malware",      value: 12, color: ACC.purple  },
  { name: "Log Evasion",  value: 8,  color: ACC.cyan    },
  { name: "Normal",       value: 5,  color: ACC.green   },
];

function buildOption(data: AttackDataItem[]): echarts.EChartsOption {
  return {
    backgroundColor: "transparent",
    tooltip: {
      trigger: "item",
      ...TT,
      formatter: "{b}<br/><b>{c}</b> events &nbsp; ({d}%)",
    },
    legend: {
      orient: "vertical",
      right: 8,
      top: "middle",
      textStyle: { color: T.md, fontSize: 10, fontFamily: "JetBrains Mono" },
      icon: "circle",
      itemWidth: 8,
      itemHeight: 8,
      itemGap: 10,
    },
    series: [{
      type: "pie",
      radius: ["44%", "70%"],
      center: ["38%", "50%"],
      data: data.map(d => ({
        value: d.value,
        name: d.name,
        itemStyle: { color: d.color },
      })),
      label: { show: false },
      emphasis: { scale: true, scaleSize: 6 },
    }],
  };
}

const AttackDistributionChart: React.FC<Props> = ({ ready, data }) => {
  const ref  = useRef<HTMLDivElement>(null);
  const inst = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (!ready || !ref.current) return;
    inst.current = echarts.init(ref.current, "dark");
    const ro = new ResizeObserver(() => inst.current?.resize());
    ro.observe(ref.current);
    return () => { ro.disconnect(); inst.current?.dispose(); inst.current = null; };
  }, [ready]);

  useEffect(() => {
    if (!inst.current) return;
    inst.current.setOption(buildOption(data ?? DEFAULT_DATA), true);
  }, [data, ready]);

  return <div ref={ref} style={{ width: "100%", height: 260 }} />;
};

export default AttackDistributionChart;
