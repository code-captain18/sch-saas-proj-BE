import type { FeeLineItem } from "../types/app-types.js";

export function sumFeeItems(items: FeeLineItem[]) {
    return items.reduce((total, item) => total + Number(item.amount), 0);
}
