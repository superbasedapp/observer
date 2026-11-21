package app.superbased.sdk;

import java.util.Collections;
import java.util.Map;

/** A dataset on one destination ({@link Superbased#getDataset}). */
public final class Dataset {
  final String id;
  final String name;
  final String side;
  final long itemCount;
  final long latestSnapshot;
  final Map<String, Object> raw;

  Dataset(String id, String name, String side, long itemCount, long latestSnapshot, Map<String, Object> raw) {
    this.id = id;
    this.name = name;
    this.side = side;
    this.itemCount = itemCount;
    this.latestSnapshot = latestSnapshot;
    this.raw = raw == null ? Map.of() : Collections.unmodifiableMap(raw);
  }

  public String id() {
    return id;
  }

  public String name() {
    return name;
  }

  /** {@code online} or {@code local}: the destination that has it. */
  public String side() {
    return side;
  }

  public long itemCount() {
    return itemCount;
  }

  public long latestSnapshot() {
    return latestSnapshot;
  }

  /** The destination's dataset object as it answered. */
  public Map<String, Object> raw() {
    return raw;
  }

  @Override
  public String toString() {
    return "Dataset{id=" + id + ", name=" + name + ", side=" + side + "}";
  }
}
