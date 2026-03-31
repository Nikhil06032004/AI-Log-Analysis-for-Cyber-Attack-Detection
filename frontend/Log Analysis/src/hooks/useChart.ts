import { useEffect, useRef, type RefObject } from "react";
import * as echarts from "echarts";

function useChart(ref: RefObject<HTMLDivElement | null>, opt: echarts.EChartsOption, ready: boolean) {
  const inst = useRef<echarts.ECharts | null>(null);
  useEffect(() => {
    if (!ready || !ref.current) return;
    if (!inst.current) inst.current = echarts.init(ref.current, "dark");
    inst.current.setOption(opt, true);
    const onResize = () => inst.current?.resize();
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready]);

  // force resize after layout settles
  useEffect(() => {
    if (!ready) return;
    const id = setTimeout(() => inst.current?.resize(), 120);
    return () => clearTimeout(id);
  }, [ready]);
}

export default useChart;
