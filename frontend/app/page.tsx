"use client"

import GridDistortion from "@/components/global/GridDistortion";
import { useRouter } from "next/navigation";

export default function Home() {

  const router = useRouter();

  const onClick = () => {
    router.push("/monitor");
  }

  return (
    <div>
      <button onClick={onClick}>
        monitor
      </button>
    </div>
  );
}
