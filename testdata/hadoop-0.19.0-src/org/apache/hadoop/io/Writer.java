/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/** A dense file-based mapping from integers to values. */
package org.apache.hadoop.io;
import java.io.*;
import org.apache.hadoop.fs.*;
import org.apache.hadoop.conf.*;
import org.apache.hadoop.util.*;
import org.apache.hadoop.io.SequenceFile.CompressionType;

public static class Writer extends MapFile.Writer {
    private LongWritable count = new LongWritable(0);

    /** Create the named file for values of the named class. */
    public Writer(Configuration conf, FileSystem fs,
                  String file, Class<? extends Writable> valClass)
      throws IOException {
      super(conf, fs, file, LongWritable.class, valClass);
    }

    /** Create the named file for values of the named class. */
    public Writer(Configuration conf, FileSystem fs,
                  String file, Class<? extends Writable> valClass,
                  CompressionType compress, Progressable progress)
      throws IOException {
      super(conf, fs, file, LongWritable.class, valClass, compress, progress);
    }

    /** Append a value to the file. */
    public synchronized void append(Writable value) throws IOException {
      super.append(count, value);                 // add to map
      count.set(count.get()+1);                   // increment count
    }
  }